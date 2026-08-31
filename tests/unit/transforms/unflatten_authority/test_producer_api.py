from __future__ import annotations

import pytest
from dataclasses import replace
from types import SimpleNamespace

from d810.analyses.control_flow.semantic_route_evidence import DecisionDagComparisonWitness

from d810.ir.flowgraph import BlockKind, BlockSnapshot, InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.transforms.unflatten_authority.model import EffectSiteKind, TerminalKind
from d810.transforms.unflatten_authority import producer_api as producer_module
from d810.transforms.unflatten_authority.model import (
    InventoryInstructionObservation,
    resolve_inventory_block_sites,
)
from d810.transforms.unflatten_authority.ids import validate_canonical_roundtrip
from d810.transforms.unflatten_authority.producer_api import (
    BootstrapEntryRouteForecast,
    ConditionalArmRouteForecast,
    ConcreteEntryRouteForecast,
    ConditionalEntryBridgeForecast,
    classify_block_effects_and_terminals,
    observe_inventory_block,
    validate_exact_effect_claim_semantics,
)


class _ForeignBootstrapEntryRouteForecast(BootstrapEntryRouteForecast):
    pass


class _ForeignConditionalEntryBridgeForecast(ConditionalEntryBridgeForecast):
    pass


def test_conditional_arm_adapter_requires_the_complete_decision_dag_witness() -> None:
    """An arm route binds its writer and every canonical DAG coordinate."""

    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidenceProductionContext,
        DecisionDagComparisonWitness,
        DecisionDagRouteWitness,
        SemanticRecoveredStateWriteWitness,
        SemanticDagNamespaceBridge,
            SemanticRouteFact,
            SemanticRouteFactKind,
            SemanticPhysicalStateWriteWitness,
        build_canonical_semantic_evidence,
        canonical_semantic_evidence_from_proofs,
    )
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.analyses.control_flow.semantic_route_evidence import SemanticDagNamespaceBridge
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import FlowGraph
    from d810.ir.flowgraph import FlowGraph
    from d810.ir.graph_fingerprint import _instruction_projection
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.graph_modification import RedirectGoto

    key = NativePreanalysisKey("conditional-arm", "x86", 64, 0, "a" * 64, "b" * 64, "c" * 64)
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    write = InsnSnapshot(
        opcode=0, ea=0x1100, operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        kind=InsnKind.MOV, value_op_kind=ValueOpKind.MOVE,
    )
    branch = InsnSnapshot(
        opcode=0, ea=0x1200, operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    blocks = {
        1: BlockSnapshot(1, 1, (2,), (), 0, 0x1100, (write,), 0, BlockKind.ONE_WAY, InsnKind.MOV, 0),
        2: BlockSnapshot(2, 2, (3, 4), (1,), 0, 0x1200, (branch,), 0, BlockKind.TWO_WAY, InsnKind.COND_JUMP, 0),
        3: BlockSnapshot(3, 0, (), (2,), 0, 0x1300, (), None, BlockKind.ZERO_WAY, None, None),
        4: BlockSnapshot(4, 0, (), (2,), 0, 0x1400, (), None, BlockKind.ZERO_WAY, None, None),
    }
    source = FlowGraph(blocks, entry_serial=1, func_ea=0x1100)
    refs = {
        serial: NativeBlockRef(StableBlockIdentity.from_intervals(
            (NativeEaInterval(block.start_ea, block.start_ea + 0x10),),
            native_key=key,
            exact_instruction_eas=tuple(item.ea for item in block.insn_snapshots),
        ))
        for serial, block in blocks.items()
    }
    catalog = producer_module.build_source_identity_catalog(source, refs, native_key=key, source_generation=1)
    raw_dag = DecisionDagRouteWitness(
        state_identity, 7, 2, 0x1200, (2,), (0x1200,),
        tuple(DecisionDagComparisonWitness(serial, comparison, state_identity) for serial, comparison in ((2, RouteComparison(2, "jz", 7, 3, 4)),)), (),
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG, 1, 1, 0x1100, 7, 3,
        0x1100, 0x1300, (1,), (), decision_dag_witness=raw_dag,
    )
    result = build_canonical_semantic_evidence(
        (fact,),
        CanonicalSemanticEvidenceProductionContext(
            key, 1, "conditional-arm", state_identity, tuple(blocks.values()),
            tuple((serial, ref.identity) for serial, ref in refs.items()), entry_serial=1,
        ),
    )
    assert result.abstention is None and result.evidence is not None
    forecast = ConditionalArmRouteForecast(RedirectGoto(1, 2, 3), 7, 3, fact)
    kwargs = dict(source=source, source_catalog=catalog, block_refs_by_serial=refs,
                  canonical_evidence=result.evidence, state_identity=state_identity)
    assert producer_module.adapt_conditional_arm_route(forecast, **kwargs) is result.evidence.route_proofs[0]

    # The producer fact is only a transport envelope: a recovered VALUE/SUB
    # witness must replay identically against the selected canonical proof.
    recovered = SemanticRecoveredStateWriteWitness(
        _instruction_projection(replace(write, kind=InsnKind.VALUE)),
        state_identity,
        4,
        8,
    )
    object.__setattr__(fact, "recovered_state_write", recovered)
    try:
        with pytest.raises(ValueError, match="zero"):
            producer_module.adapt_conditional_arm_route(forecast, **kwargs)
    finally:
        object.__setattr__(fact, "recovered_state_write", None)

    for field, value in (("source_instruction_ea", 0x1101), ("target_serial", 4)):
        with pytest.raises(ValueError):
            producer_module.adapt_conditional_arm_route(replace(forecast, route_fact=replace(fact, **{field: value})), **kwargs)
    altered_dag = replace(raw_dag, path_anchors=(0x1201,))
    with pytest.raises(ValueError):
        producer_module.adapt_conditional_arm_route(replace(forecast, route_fact=replace(fact, decision_dag_witness=altered_dag)), **kwargs)

    proof = result.evidence.route_proofs[0]
    assert proof.state_dag is not None
    (comparison,) = proof.state_dag.witness.comparisons
    drifted_comparison = replace(
        comparison,
        node=replace(comparison.node, anchor_ea=0x1201),
    )
    drifted_witness = replace(
        proof.state_dag.witness,
        comparisons=(drifted_comparison,),
    )
    drifted_proof = replace(
        proof,
        state_dag=replace(proof.state_dag, witness=drifted_witness),
    )
    drifted_evidence = canonical_semantic_evidence_from_proofs(
        result.evidence.native_key,
        result.evidence.generation,
        (drifted_proof,),
    )
    with pytest.raises(ValueError):
        producer_module.adapt_conditional_arm_route(
            forecast,
            **{**kwargs, "canonical_evidence": drifted_evidence},
        )
    for drifted_witness in (
        replace(
            proof.state_dag.witness,
            comparisons=(replace(
                comparison,
                state_identity=StorageIdentity(StorageIdentityKind.REGISTER, 4),
            ),),
        ),
        replace(
            proof.state_dag.witness,
            bridges=(SemanticDagNamespaceBridge(
                comparison.node,
                0x1200,
                state_identity,
                StorageIdentity(StorageIdentityKind.REGISTER, 4),
                4,
                8,
            ),),
        ),
    ):
        with pytest.raises(ValueError, match="zero"):
            producer_module.adapt_conditional_arm_route(
                forecast,
                **{**kwargs, "canonical_evidence": canonical_semantic_evidence_from_proofs(
                    result.evidence.native_key,
                    result.evidence.generation,
                    (replace(proof, state_dag=replace(proof.state_dag, witness=drifted_witness)),),
                )},
            )


def test_conditional_arm_adapter_binds_exact_logical_function_exit_endpoint() -> None:
    """The producer selects a native route with a logical exit sibling."""

    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidenceProductionContext, DecisionDagRouteWitness,
        SemanticDagEndpointKind, SemanticLogicalDagEndpoint, SemanticRouteFact,
        SemanticRouteFactKind, build_canonical_semantic_evidence,
    )
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import FlowGraph
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
    from d810.transforms.graph_modification import RedirectGoto

    key = NativePreanalysisKey("logical-arm", "x86", 64, 0, "a" * 64, "b" * 64, "c" * 64)
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    write = InsnSnapshot(0, 0x1100, (), l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8), d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40), kind=InsnKind.MOV)
    branch = InsnSnapshot(0, 0x1200, (), l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40), r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7), d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4), kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ, is_conditional_jump=True)
    blocks = {
        1: BlockSnapshot(1, 1, (2,), (), 0, 0x1100, (write,), 0, BlockKind.ONE_WAY, InsnKind.MOV, 0),
        2: BlockSnapshot(2, 2, (4, 3), (1,), 0, 0x1200, (branch,), 0, BlockKind.TWO_WAY, InsnKind.COND_JUMP, 0),
        3: BlockSnapshot(3, 0, (), (2,), 0, 0x1300, (), None, BlockKind.ZERO_WAY, None, None),
        4: BlockSnapshot(4, 0, (), (2,), 0, 0xFFFFFFFFFFFFFFFF, (), None, BlockKind.ZERO_WAY, None, None),
    }
    source = FlowGraph(blocks, entry_serial=1, func_ea=0x1100)
    refs = {
        serial: NativeBlockRef(StableBlockIdentity.from_intervals((NativeEaInterval(block.start_ea, block.start_ea + 0x10),), native_key=key, exact_instruction_eas=tuple(item.ea for item in block.insn_snapshots)))
        for serial, block in blocks.items() if serial != 4
    }
    refs[4] = LogicalBlockRef("logical-arm", "function-exit", 0)
    endpoint = SemanticLogicalDagEndpoint(SemanticDagEndpointKind.FUNCTION_EXIT, 4, "logical-arm", "function-exit", 0)
    context = CanonicalSemanticEvidenceProductionContext(key, 1, "logical-arm", state, tuple(blocks.values()), tuple((serial, ref.identity) for serial, ref in refs.items() if type(ref) is NativeBlockRef), logical_endpoints_by_serial=((4, endpoint),), entry_serial=1)
    fact = SemanticRouteFact(SemanticRouteFactKind.DECISION_DAG, 1, 1, 0x1100, 8, 3, 0x1100, 0x1300, (1,), (), decision_dag_witness=DecisionDagRouteWitness(state, 8, 2, 0x1200, (2,), (0x1200,), tuple(DecisionDagComparisonWitness(serial, comparison, state) for serial, comparison in ((2, RouteComparison(2, "jz", 7, 4, 3)),)), ()))
    evidence = build_canonical_semantic_evidence((fact,), context).evidence
    assert evidence is not None
    catalog = producer_module.build_source_identity_catalog(source, refs, native_key=key, source_generation=1)
    forecast = ConditionalArmRouteForecast(RedirectGoto(1, 2, 3), 8, 3, fact)
    kwargs = dict(source=source, source_catalog=catalog, block_refs_by_serial=refs, canonical_evidence=evidence, state_identity=state)
    assert producer_module.adapt_conditional_arm_route(forecast, **kwargs) is evidence.route_proofs[0]
    drifted = {**refs, 4: LogicalBlockRef("logical-arm", "function-exit", 1)}
    with pytest.raises(ValueError):
        producer_module.adapt_conditional_arm_route(forecast, **{**kwargs, "block_refs_by_serial": drifted})


def _block(*instructions: InsnSnapshot, kind: BlockKind = BlockKind.UNKNOWN, succs: tuple[int, ...] = ()) -> BlockSnapshot:
    instructions = tuple(
        replace(item, raw_opcode=item.opcode)
        if isinstance(item, InsnSnapshot)
        and item.raw_opcode is None and item.opcode >= 0
        else item
        for item in instructions
    )
    tail = instructions[-1] if instructions else None
    return BlockSnapshot(
        1, 0, succs, (), 0, 0x1000, instructions,
        tail_opcode=tail.opcode if tail else None,
        kind=kind,
        tail_kind=tail.kind if tail else None,
        raw_tail_opcode=getattr(tail, "raw_opcode", None) if tail else None,
    )


def _native_bound_concrete_entry_fixture():
    """Build one concrete-entry receipt with one same-block physical U32 MOV."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidenceProductionContext,
        SemanticPhysicalStateWriteWitness,
        SemanticRouteFact,
        SemanticRouteFactKind,
        build_canonical_semantic_evidence,
    )
    from d810.analyses.control_flow import semantic_route_evidence as route_model
    from d810.ir.expressions import ValueOpKind
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source_seed, proposal, _exclusion, refs = exact_fixture()
    state = proposal.route_evidence.route_proofs[0].state_write.state_variable
    blocks = dict(source_seed.blocks)
    first, branch = blocks[1].insn_snapshots
    physical_write = replace(
        first,
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
    )
    blocks[1] = replace(blocks[1], insn_snapshots=(physical_write, branch))
    source = type(source_seed)(blocks, source_seed.entry_serial, source_seed.func_ea)
    fact = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND,
        1, 1, 0x2000, 7, 2, 0x2000, 0x3000, (1,), (),
        "entry-prefix-fact",
        physical_state_write=SemanticPhysicalStateWriteWitness(
            route_model._instruction_projection(physical_write), state, 4, 7,
        ),
    )
    result = build_canonical_semantic_evidence(
        (fact,),
        CanonicalSemanticEvidenceProductionContext(
            proposal.route_evidence.native_key,
            proposal.route_evidence.generation,
            "native-bound:concrete-entry",
            state,
            tuple(source.blocks.values()),
            tuple((serial, ref.identity) for serial, ref in refs.items()),
            source.entry_serial,
        ),
    )
    assert result.abstention is None and result.evidence is not None
    return (
        source,
        producer_api.build_source_identity_catalog(
            source,
            refs,
            native_key=proposal.route_evidence.native_key,
            source_generation=proposal.route_evidence.generation,
        ),
        refs,
        result.evidence,
        state,
    )


def _carrier_concrete_entry_fixture():
    """Build one exact carrier-owned concrete entry route."""

    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidenceProductionContext,
        SemanticRouteFact,
        SemanticRouteFactKind,
        build_canonical_semantic_evidence,
    )
    from d810.analyses.control_flow.state_carrier import ExactCarrierStateWrite
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import FlowGraph
    from d810.ir.semantic_edge import SemanticEdgeRole
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.ir.varnode import Space, Varnode
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    _seed, proposal, _exclusion, _seed_refs = exact_fixture()
    key = proposal.route_evidence.native_key
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 4)
    carrier = Varnode(Space.REGISTER, 8, 4)
    prefix = InsnSnapshot(0, 0x1FF0, (), kind=InsnKind.NOP, raw_opcode=0)
    const = InsnSnapshot(
        0,
        0x2000,
        (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        raw_opcode=0,
    )
    source_goto = InsnSnapshot(
        0,
        0x2001,
        (),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.GOTO,
        raw_opcode=0,
    )
    delivery = InsnSnapshot(
        0,
        0x2500,
        (),
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        raw_opcode=0,
    )
    blocks = {
        1: BlockSnapshot(
            1, 0, (3,), (), 0, 0x1F00, (prefix, const, source_goto),
        ),
        3: BlockSnapshot(3, 0, (4,), (1,), 0, 0x2500, (delivery,)),
        4: BlockSnapshot(
            4, 0, (2,), (3,), 0, 0x2800,
            (InsnSnapshot(0, 0x2800, (), kind=InsnKind.NOP, raw_opcode=0),),
        ),
        2: BlockSnapshot(
            2, 0, (), (4,), 0, 0x3000,
            (InsnSnapshot(0, 0x3000, (), kind=InsnKind.NOP, raw_opcode=0),),
        ),
    }
    source = FlowGraph(blocks, entry_serial=1, func_ea=0x2000)
    refs = {
        serial: NativeBlockRef(
            StableBlockIdentity.from_intervals(
                (NativeEaInterval(0x1F00, 0x2002),),
                native_key=key,
                exact_instruction_eas=(0x1FF0, 0x2000, 0x2001),
            )
            if serial == 1
            else StableBlockIdentity.from_instruction_eas(
                tuple(int(insn.ea) for insn in block.insn_snapshots),
                native_key=key,
            )
        )
        for serial, block in blocks.items()
    }
    witness = ExactCarrierStateWrite(
        state=7,
        source_serial=1,
        source_instruction_ea=0x2000,
        feeder_serial=3,
        comparison_entry_serial=4,
        carrier=carrier,
        state_identity=state_identity,
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.STATE_CARRIER,
        1, 1, 0x2000, 7, 2, 0x1F00, 0x3000, (1,), (),
        fact_id="entry-carrier-fact",
        carrier_witness=witness,
    )
    result = build_canonical_semantic_evidence(
        (fact,),
        CanonicalSemanticEvidenceProductionContext(
            key,
            proposal.route_evidence.generation,
            "native-bound:carrier-entry",
            state_identity,
            tuple(blocks.values()),
            tuple((serial, ref.identity) for serial, ref in refs.items()),
            source.entry_serial,
        ),
    )
    assert result.abstention is None and result.evidence is not None
    proof = result.evidence.route_proofs[0]
    assert proof.destinations[0].role is SemanticEdgeRole.DIRECT
    assert proof.state_carrier is not None
    assert proof.state_carrier.owner_anchor_ea == 0x1F00
    assert proof.state_carrier.source_anchor_ea == 0x2000
    return (
        source,
        producer_api.build_source_identity_catalog(
            source,
            refs,
            native_key=key,
            source_generation=proposal.route_evidence.generation,
        ),
        refs,
        result.evidence,
        state_identity,
    )


def test_concrete_entry_route_owns_its_exact_rebound_predecessor_proof() -> None:
    """Entry-prefix authority is selected by its physical fact, not a back edge."""

    from d810.transforms.unflatten_authority import producer_api

    source, source_catalog, refs, evidence, state = _native_bound_concrete_entry_fixture()
    proof = evidence.route_proofs[0]
    entry = ConcreteEntryRouteForecast(
        normalized_state=7,
        target_handler=2,
        source_kinds=("native_bound",),
        physical_fact_id="entry-prefix-fact",
        canonical_proof_id=proof.proof_id,
        source_identity=refs[1].identity,
        source_anchor_ea=0x2000,
        target_identity=refs[2].identity,
        state_identity=state,
        proof_owner_identity="entry-prefix:blk1@0x2000",
    )

    # The unrelated selected-backedge index is intentionally empty.  A concrete
    # entry owns the exact canonical proof named by its rebound physical fact.
    owners: dict[str, str] = {}
    resolved = producer_api.resolve_concrete_entry_route(
        entry,
        source=source,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=evidence,
        selected_transitions=producer_api.TransitionRouteSelectionIndex(()),
        proof_owners=owners,
    )
    assert resolved.proof_id == proof.proof_id
    assert owners == {resolved.proof_id: "entry-prefix:blk1@0x2000"}


def test_concrete_entry_route_owns_exact_carrier_proof() -> None:
    """Concrete entry consumes STATE_CARRIER without relabeling it as a write."""

    from d810.transforms.unflatten_authority import producer_api

    source, source_catalog, refs, evidence, state = _carrier_concrete_entry_fixture()
    proof = evidence.route_proofs[0]
    route = ConcreteEntryRouteForecast(
        7,
        2,
        ("native_bound", "source_carrier"),
        "entry-carrier-fact",
        proof.proof_id,
        refs[1].identity,
        0x2000,
        refs[2].identity,
        state,
        "entry-carrier:blk1@0x2000",
    )
    owners: dict[str, str] = {}

    resolved = producer_api.resolve_concrete_entry_route(
        route,
        source=source,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=evidence,
        selected_transitions=producer_api.TransitionRouteSelectionIndex(()),
        proof_owners=owners,
    )

    assert resolved is proof
    assert resolved.state_write is None
    assert resolved.state_carrier is not None
    assert owners == {proof.proof_id: "entry-carrier:blk1@0x2000"}


def test_concrete_entry_carrier_rejects_identity_state_anchor_target_and_owner_drift() -> None:
    """Every forecast coordinate and ownership handle remains relation-bound."""

    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.unflatten_authority import producer_api

    source, source_catalog, refs, evidence, state = _carrier_concrete_entry_fixture()
    proof = evidence.route_proofs[0]
    route = ConcreteEntryRouteForecast(
        7,
        2,
        ("native_bound", "source_carrier"),
        "entry-carrier-fact",
        proof.proof_id,
        refs[1].identity,
        0x2000,
        refs[2].identity,
        state,
        "entry-carrier:blk1@0x2000",
    )
    kwargs = dict(
        source=source,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=evidence,
        selected_transitions=producer_api.TransitionRouteSelectionIndex(()),
    )

    for drifted in (
        replace(route, normalized_state=8),
        replace(route, state_identity=StorageIdentity(StorageIdentityKind.REGISTER, 8)),
        replace(route, source_anchor_ea=0x2001),
        replace(route, target_handler=4, target_identity=refs[4].identity),
        replace(route, canonical_proof_id="missing-carrier-proof"),
    ):
        with pytest.raises(ValueError):
            producer_api.resolve_concrete_entry_route(
                drifted,
                proof_owners={},
                **kwargs,
            )

    carrier = proof.state_carrier
    assert carrier is not None
    original_owner = carrier.owner_identity
    object.__setattr__(carrier, "owner_identity", refs[3].identity)
    try:
        with pytest.raises(ValueError, match="source/state"):
            producer_api.resolve_concrete_entry_route(
                route,
                proof_owners={},
                **kwargs,
            )
    finally:
        object.__setattr__(carrier, "owner_identity", original_owner)

    original_owner_anchor = carrier.owner_anchor_ea
    object.__setattr__(carrier, "owner_anchor_ea", 0x1FF1)
    try:
        with pytest.raises(ValueError, match="source/state"):
            producer_api.resolve_concrete_entry_route(
                route,
                proof_owners={},
                **kwargs,
            )
    finally:
        object.__setattr__(carrier, "owner_anchor_ea", original_owner_anchor)

    original_corridor = carrier.corridor
    object.__setattr__(
        carrier,
        "corridor",
        (original_corridor[0], original_corridor[2], original_corridor[1]),
    )
    try:
        with pytest.raises(ValueError):
            producer_api.resolve_concrete_entry_route(
                route,
                proof_owners={},
                **kwargs,
            )
    finally:
        object.__setattr__(carrier, "corridor", original_corridor)

    with pytest.raises(ValueError, match="already owned"):
        producer_api.resolve_concrete_entry_route(
            route,
            proof_owners={proof.proof_id: "backedge-owner"},
            **kwargs,
        )


def test_concrete_entry_route_rejects_missing_ambiguous_drifted_or_duplicate_owners() -> None:
    """Concrete-entry proof selection has no state/target fallback or shared owner."""

    from d810.transforms.unflatten_authority import producer_api

    source, source_catalog, refs, evidence, state = _native_bound_concrete_entry_fixture()
    proof = evidence.route_proofs[0]
    route = ConcreteEntryRouteForecast(
        7, 2, ("native_bound",), "entry-prefix-fact",
        proof.proof_id, refs[1].identity,
        0x2000, refs[2].identity, state,
        "entry-prefix:blk1@0x2000",
    )
    kwargs = dict(
        source=source,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=evidence,
        selected_transitions=producer_api.TransitionRouteSelectionIndex(()),
    )

    with pytest.raises(ValueError, match="canonical physical"):
        producer_api.resolve_concrete_entry_route(
            replace(route, canonical_proof_id="missing"), proof_owners={}, **kwargs,
        )
    with pytest.raises(ValueError, match="state"):
        producer_api.resolve_concrete_entry_route(
            replace(route, normalized_state=8), proof_owners={}, **kwargs,
        )
    with pytest.raises(ValueError, match="target/state"):
        producer_api.resolve_concrete_entry_route(
            replace(route, target_handler=3, target_identity=refs[3].identity),
            proof_owners={}, **kwargs,
        )
    state_write = proof.state_write
    assert state_write is not None
    original_identity = state_write.identity
    object.__setattr__(state_write, "identity", refs[0].identity)
    try:
        with pytest.raises(ValueError, match="source/state"):
            producer_api.resolve_concrete_entry_route(route, proof_owners={}, **kwargs)
    finally:
        object.__setattr__(state_write, "identity", original_identity)
    with pytest.raises(ValueError, match="already owned"):
        producer_api.resolve_concrete_entry_route(
            route, proof_owners={proof.proof_id: "backedge"}, **kwargs,
        )
    owners: dict[str, str] = {}
    producer_api.resolve_concrete_entry_route(route, proof_owners=owners, **kwargs)
    with pytest.raises(ValueError, match="already owned"):
        producer_api.resolve_concrete_entry_route(
            replace(route, proof_owner_identity="second-entry"),
            proof_owners=owners,
            **kwargs,
        )


@pytest.mark.parametrize(
    ("insn_kind", "effect_kind", "terminal_kind"),
    [
        (InsnKind.STORE, EffectSiteKind.STORE, None),
        (InsnKind.TRAP, EffectSiteKind.TRAP, TerminalKind.TRAP),
        (InsnKind.RET, EffectSiteKind.RETURN, TerminalKind.RETURN),
        (InsnKind.CALL, EffectSiteKind.CALL, TerminalKind.NORETURN_CALL),
    ],
)
def test_classifier_emits_exact_effect_and_terminal_rows(
    insn_kind: InsnKind, effect_kind: EffectSiteKind, terminal_kind: TerminalKind | None,
) -> None:
    insn = InsnSnapshot(0x42, 0x1000, (), kind=insn_kind, l=MopSnapshot(size=2), r=MopSnapshot(size=4))
    effects, terminals = classify_block_effects_and_terminals(_block(insn), owner_ref=None, owner_anchor_ea=0x1000)
    assert len(effects) == 1
    assert effects[0].effect_kind is effect_kind
    assert effects[0].opcode == 0x42
    assert effects[0].width == 4
    if terminal_kind is None:
        assert terminals == ()
    else:
        assert terminals[0].terminal_kind is terminal_kind


def test_route_witness_accepts_unique_native_endpoint_anchor_in_identity_range() -> None:
    """Physical-entry anchors may precede the first instruction origin."""

    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority.model import (
        SourceBlockIdentityWitness,
        SourceIdentityCatalog,
    )

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1010),),
        native_key=key,
        exact_instruction_eas=(),
    )
    ref = NativeBlockRef(identity)
    catalog = SourceIdentityCatalog(
        native_key=key,
        generation=1,
        blocks=(SourceBlockIdentityWitness(ref, 0x1000, ()),),
    )

    witness = producer_module._route_witness(catalog, identity, 0x1008)

    assert witness.block_ref is ref
    assert witness.anchor_ea == 0x1000
    with pytest.raises(ValueError, match="missing or ambiguous"):
        producer_module._route_witness(catalog, identity, 0x1010)

    instruction_identity = StableBlockIdentity.from_instruction_eas(
        (0x1000,), native_key=key,
    )
    instruction_ref = NativeBlockRef(instruction_identity)
    instruction_catalog = SourceIdentityCatalog(
        native_key=key,
        generation=1,
        blocks=(SourceBlockIdentityWitness(instruction_ref, 0x1000, (0x1000,)),),
    )
    with pytest.raises(ValueError, match="missing or ambiguous"):
        producer_module._route_witness(instruction_catalog, instruction_identity, 0x1008)

    physical_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x2000, 0x2010),),
        native_key=key,
        exact_instruction_eas=(0x2008,),
    )
    physical_ref = NativeBlockRef(physical_identity)
    physical_catalog = SourceIdentityCatalog(
        native_key=key,
        generation=1,
        blocks=(SourceBlockIdentityWitness(physical_ref, 0x2008, (0x2008,)),),
    )
    physical_witness = producer_module._route_witness(
        physical_catalog, physical_identity, 0x2000,
    )
    assert physical_witness.block_ref is physical_ref


def test_source_catalog_uses_physical_native_entry_before_instruction_origin() -> None:
    """Dispatcher coverage and route consumers share the physical entry anchor."""

    from dataclasses import replace

    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.transforms.cfg_transaction import NativeBlockRef

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    block = BlockSnapshot(
        0, 0, (), (), 0, 0x1000,
        (InsnSnapshot(0, 0x1004, (), kind=InsnKind.NOP),),
        tail_opcode=0,
        kind=BlockKind.ZERO_WAY,
        tail_kind=InsnKind.NOP,
        raw_tail_opcode=None,
    )
    source = FlowGraph({0: replace(block, native_start_ea=0x1000)}, 0, 0x1000)
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1020),),
        native_key=key,
        exact_instruction_eas=(0x1004,),
    )
    catalog = producer_module.build_source_identity_catalog(
        source,
        {0: NativeBlockRef(identity)},
        native_key=key,
        source_generation=1,
    )
    assert catalog.blocks[0].anchor_ea == 0x1000
    assert catalog.blocks[0].native_instruction_eas == (0x1004,)


def test_source_catalog_allows_distinct_native_refs_to_share_native_instruction_origin() -> None:
    from dataclasses import replace

    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
    from d810.transforms.cfg_transaction import NativeBlockRef

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    source = FlowGraph(
        {
            0: BlockSnapshot(0, 0, (), (), 0, 0x1000, (InsnSnapshot(0, 0x1004, (), kind=InsnKind.NOP),), tail_opcode=0, kind=BlockKind.ZERO_WAY, tail_kind=InsnKind.NOP, raw_tail_opcode=None),
            1: BlockSnapshot(1, 0, (), (), 0, 0x1010, (InsnSnapshot(0, 0x1014, (), kind=InsnKind.NOP),), tail_opcode=0, kind=BlockKind.ZERO_WAY, tail_kind=InsnKind.NOP, raw_tail_opcode=None),
        },
        0,
        0x1000,
    )
    refs = {
        0: NativeBlockRef(StableBlockIdentity.from_intervals((NativeEaInterval(0x1000, 0x1010),), native_key=key, exact_instruction_eas=(0x1004,))),
        1: NativeBlockRef(StableBlockIdentity.from_intervals((NativeEaInterval(0x1000, 0x1020),), native_key=key, exact_instruction_eas=(0x1014,))),
    }
    catalog = producer_module.build_source_identity_catalog(
        source, refs, native_key=key, source_generation=1,
    )
    assert tuple(item.anchor_ea for item in catalog.blocks) == (0x1000, 0x1010)

    overlapping = {
        1: NativeBlockRef(StableBlockIdentity.from_intervals((NativeEaInterval(0x1000, 0x1020),), native_key=key, exact_instruction_eas=(0x1004,)))
    }
    overlapping_source = replace(
        source,
        blocks={
            **source.blocks,
            1: replace(
                source.blocks[1],
                insn_snapshots=(InsnSnapshot(0, 0x1004, (), kind=InsnKind.NOP),),
            ),
        },
    )
    overlapping_catalog = producer_module.build_source_identity_catalog(
        overlapping_source,
        {0: refs[0], **overlapping},
        native_key=key,
        source_generation=1,
    )
    assert tuple(
        item.native_instruction_eas for item in overlapping_catalog.blocks
    ) == ((0x1004,), (0x1004,))


def test_equivalent_route_claims_normalize_selected_proofs_without_graph_rebind() -> None:
    """Claim construction owns catalog identity only; SOURCE owns topology."""

    from dataclasses import replace
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, _refs = exact_fixture()
    drifted = replace(
        source,
        blocks={
            **source.blocks,
            0: replace(source.blocks[0], succs=()),
        },
    )
    proof_id = proposal.route_evidence.route_proofs[0].proof_id
    claims = producer_module.build_equivalent_route_claims(
        source=drifted,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        selected_proof_ids=(proof_id,),
    )
    assert len(claims) == 1


def test_clean_use_def_redirect_digest_is_order_invariant_and_canonically_stable() -> None:
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.use_def_redirect_filter import UseDefSeveranceAudit

    refs = (
        LogicalBlockRef("use-def-session", "owner-b", 2),
        LogicalBlockRef("use-def-session", "owner-a", 1),
    )
    audit = UseDefSeveranceAudit(True, 0)
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    first = producer_module.build_use_def_fragment_witness(
        audit,
        fragment_id="sha256:" + "1" * 64,
        state_identity=state_identity,
        redirect_owner_refs=refs,
    )
    second = producer_module.build_use_def_fragment_witness(
        audit,
        fragment_id="sha256:" + "1" * 64,
        state_identity=state_identity,
        redirect_owner_refs=tuple(reversed(refs)),
    )
    assert first is not None and second is not None
    assert first.redirect_digest == second.redirect_digest
    assert validate_canonical_roundtrip(
        first, type(first),
    ) == first


def test_classifier_emits_call_terminal_and_synthesized_stop() -> None:
    call = InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.CALL)
    effects, terminals = classify_block_effects_and_terminals(
        _block(call, kind=BlockKind.STOP), owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects[0].effect_kind is EffectSiteKind.CALL
    assert {item.terminal_kind for item in terminals} == {TerminalKind.NORETURN_CALL}

    effects, terminals = classify_block_effects_and_terminals(
        _block(kind=BlockKind.STOP), owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects == ()
    assert terminals[0].terminal_kind is TerminalKind.STOP
    assert terminals[0].instruction_ordinal is None


def test_inventory_adapter_retains_generated_candidate_control_transfer_without_ea() -> None:
    generated = BlockSnapshot(
        7, 0, (8,), (), 0, 0xFFFFFFFFFFFFFFFF,
        (InsnSnapshot(
            0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.GOTO,
            raw_opcode=0x42,
            control_transfer_kind=ControlTransferKind.GOTO,
        ),),
        tail_opcode=0x42,
        kind=BlockKind.UNKNOWN,
        tail_kind=InsnKind.GOTO,
        raw_tail_opcode=0x42,
    )
    observed = producer_module.observe_inventory_block(
        generated, owner_ref=None, owner_anchor_ea=None,
    )
    assert observed.successor_serials == (8,)
    assert observed.transfer_ea is None
    assert observed.instruction_observations[0].instruction_ea is None
    assert observed.instruction_observations[0].control_transfer_kind is ControlTransferKind.GOTO


def test_inventory_adapter_omits_nonunique_native_tail_transfer_ea() -> None:
    """A shared native EA cannot falsely identify the exact transfer tail."""

    block = _block(
        InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.NOP),
        InsnSnapshot(
            0x43, 0x1000, (), kind=InsnKind.GOTO,
            control_transfer_kind=ControlTransferKind.GOTO,
        ),
        kind=BlockKind.ONE_WAY,
        succs=(2,),
    )

    observed = observe_inventory_block(
        block, owner_ref=None, owner_anchor_ea=0x1000,
    )

    assert observed.native_instruction_eas == (0x1000,)
    assert observed.instruction_observations[-1].instruction_ea is None
    assert observed.transfer_ea is None


def test_inventory_adapter_leaves_non_stack_equality_branch_unclassified() -> None:
    """A native equality branch is not implicitly a synthetic state predicate."""

    block = _block(
        InsnSnapshot(
            0x43, 0x1000, (),
            l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=1),
            r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
            kind=InsnKind.COND_JUMP,
            branch_predicate=PredicateKind.EQ,
            is_conditional_jump=True,
        ),
        kind=BlockKind.TWO_WAY,
        succs=(2, 3),
    )

    observed = observe_inventory_block(
        block, owner_ref=None, owner_anchor_ea=0x1000,
    )

    assert observed.transfer_ea == 0x1000
    assert observed.instruction_observations[-1].predicate_observation is None


def test_inventory_adapter_preserves_raw_opcode_absence_and_rejects_invented_tail_provenance() -> None:
    instruction = InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.NOP, raw_opcode=0x99)
    block = _block(instruction)
    observed = observe_inventory_block(block, owner_ref=None, owner_anchor_ea=0x1000)
    assert observed.instruction_observations[0].raw_opcode == 0x99
    assert observed.raw_tail_opcode == 0x99

    missing = BlockSnapshot(
        1, 0, (), (), 0, 0x1000,
        (InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.NOP),),
        tail_opcode=0x42, kind=BlockKind.ZERO_WAY,
        tail_kind=InsnKind.NOP, raw_tail_opcode=None,
    )
    with pytest.raises(ValueError, match="raw opcode"):
        observe_inventory_block(missing, owner_ref=None, owner_anchor_ea=0x1000)

    with pytest.raises(ValueError, match="raw tail provenance"):
        observe_inventory_block(
            replace(block, raw_tail_opcode=None),
            owner_ref=None,
            owner_anchor_ea=0x1000,
        )
    with pytest.raises(ValueError, match="raw opcode"):
        observe_inventory_block(
            replace(
                block,
                insn_snapshots=(replace(instruction, raw_opcode=None),),
            ),
            owner_ref=None,
            owner_anchor_ea=0x1000,
        )


@pytest.mark.parametrize(
    "field",
    ("tail_opcode", "raw_tail_opcode", "tail_kind"),
)
def test_inventory_adapter_rejects_block_only_tail_metadata_mutation(field: str) -> None:
    instruction = InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.NOP, raw_opcode=0x99)
    block = _block(instruction)
    values = {
        "tail_opcode": 0x43,
        "raw_tail_opcode": 0x98,
        "tail_kind": InsnKind.GOTO,
    }
    with pytest.raises(ValueError):
        observe_inventory_block(
            replace(block, **{field: values[field]}),
            owner_ref=None,
            owner_anchor_ea=0x1000,
        )


def test_classifier_uses_return_transfer_and_rejects_overlap_or_missing_ea() -> None:
    with pytest.raises(TypeError):
        classify_block_effects_and_terminals(
            _block(SimpleNamespace(kind=InsnKind.STORE, native_ea=0x1000, ea=0x1000, opcode=1)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )
    effects, terminals = classify_block_effects_and_terminals(
        _block(InsnSnapshot(0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.NOP)),
        owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects == () and terminals == ()
    returned = InsnSnapshot(0x42, 0x1000, (), control_transfer_kind=ControlTransferKind.RETURN)
    effects, terminals = classify_block_effects_and_terminals(_block(returned), owner_ref=None, owner_anchor_ea=0x1000)
    assert effects[0].effect_kind is EffectSiteKind.RETURN
    assert terminals[0].terminal_kind is TerminalKind.RETURN

    with pytest.raises(ValueError, match="overlap"):
        classify_block_effects_and_terminals(
            _block(InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE, is_call=True)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )
    with pytest.raises(ValueError, match="native"):
        classify_block_effects_and_terminals(
            _block(InsnSnapshot(0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.STORE)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )

    with pytest.raises(ValueError, match="duplicate"):
        classify_block_effects_and_terminals(
            _block(
                InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE),
                InsnSnapshot(0x43, 0x1000, (), kind=InsnKind.STORE),
            ),
            owner_ref=None, owner_anchor_ea=0x1000,
        )


def test_classifier_revalidates_corrupted_empty_block_scalars() -> None:
    block = _block()
    object.__setattr__(block, "serial", -1)
    with pytest.raises(ValueError):
        classify_block_effects_and_terminals(block, owner_ref=None, owner_anchor_ea=0x1000)


def test_producer_classifier_delegates_to_one_neutral_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []
    original = producer_module.resolve_inventory_block_sites

    def spy(**kwargs: object) -> object:
        calls.append(tuple(kwargs["instruction_observations"]))
        return original(**kwargs)

    monkeypatch.setattr(producer_module, "resolve_inventory_block_sites", spy)
    block = _block(InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE))
    effects, terminals = classify_block_effects_and_terminals(
        block, owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert len(calls) == 1
    rows = calls[0]
    assert all(type(row) is InventoryInstructionObservation for row in rows)
    expected = resolve_inventory_block_sites(
        serial=block.serial, owner_ref=None, owner_anchor_ea=0x1000,
        block_kind=block.kind, successor_serials=block.succs,
        instruction_observations=rows,
    )
    assert (effects, terminals) == expected


def test_inventory_uses_access_value_width_not_pointer_width() -> None:
    load = InsnSnapshot(
        0x41, 0x1000, (), kind=InsnKind.LOAD,
        r=MopSnapshot(kind=OperandKind.LVAR, size=8),
        d=MopSnapshot(kind=OperandKind.LVAR, size=4),
    )
    store = InsnSnapshot(
        0x42, 0x1004, (), kind=InsnKind.STORE,
        l=MopSnapshot(kind=OperandKind.LVAR, size=4),
        d=MopSnapshot(kind=OperandKind.LVAR, size=8),
    )

    observed = observe_inventory_block(
        _block(load, store), owner_ref=None, owner_anchor_ea=0x1000,
    )

    assert tuple(row.width for row in observed.instruction_observations) == (4, 4)


def test_projected_conditional_inventory_carries_ordered_predicate_observation() -> None:
    from d810.ir.semantics import PredicateKind
    from d810.transforms.edit_simulator import project_post_state
    from d810.transforms.graph_modification import SyntheticStackValueEqualsCondition
    from d810.transforms.plan import LowerConditionalStateTransition
    from tests.typed_patch_authority import compile_patch_plan
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, _proposal, _exclusion, refs = exact_fixture()
    plan = compile_patch_plan(
        [
            LowerConditionalStateTransition(
                source_serial=0,
                old_dispatcher_serial=1,
                rewrite_from_ea=0x1001,
                condition_operand=SyntheticStackValueEqualsCondition(4, 4, 7),
                false_target_serial=3,
                true_target_serial=2,
            ),
        ],
        source,
    )
    projected = project_post_state(source, plan)
    observation = observe_inventory_block(
        projected.blocks[0], owner_ref=refs[0], owner_anchor_ea=0x1000,
    )

    assert observation.successor_serials == (3, 2)
    predicate = observation.instruction_observations[-1].predicate_observation
    assert predicate is not None
    assert predicate.predicate_kind is PredicateKind.EQ
    assert predicate.storage_identity.key == "S4"
    assert predicate.width == 4
    assert predicate.compare_constant == 7
    assert predicate.explicit_target_serial == 2


def test_predicate_observation_invariants_pin_order_tail_and_closed_kind() -> None:
    """Predicate facts are valid only for the exact ordered conditional tail."""
    from dataclasses import replace
    from d810.ir.semantics import PredicateKind
    from d810.transforms.edit_simulator import project_post_state
    from d810.transforms.graph_modification import SyntheticStackValueEqualsCondition
    from d810.transforms.plan import LowerConditionalStateTransition
    from tests.typed_patch_authority import compile_patch_plan
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, _proposal, _exclusion, refs = exact_fixture()
    plan = compile_patch_plan(
        [LowerConditionalStateTransition(
            source_serial=0, old_dispatcher_serial=1, rewrite_from_ea=0x1001,
            condition_operand=SyntheticStackValueEqualsCondition(4, 4, 7),
            false_target_serial=3, true_target_serial=2,
        )],
        source,
    )
    projected = project_post_state(source, plan)
    observation = observe_inventory_block(
        projected.blocks[0], owner_ref=refs[0], owner_anchor_ea=0x1000,
    )
    tail = observation.instruction_observations[-1]
    predicate = tail.predicate_observation
    assert predicate is not None

    with pytest.raises(ValueError, match="explicit target"):
        replace(observation, successor_serials=(2, 3))
    with pytest.raises(ValueError, match="conditional transfer tail"):
        replace(observation, instruction_observations=(
            *observation.instruction_observations[:-1],
            replace(tail, control_transfer_kind=None),
        ))
    with pytest.raises(ValueError, match="requires EQ"):
        replace(observation, instruction_observations=(
            *observation.instruction_observations[:-1],
            replace(tail, predicate_observation=replace(predicate, predicate_kind=PredicateKind.NE)),
        ))


def test_classifier_rejects_non_tail_control_transfer() -> None:
    block = _block(
        InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.GOTO),
        InsnSnapshot(0x43, 0x1004, (), kind=InsnKind.NOP),
        succs=(2,),
    )
    with pytest.raises(ValueError, match="tail"):
        classify_block_effects_and_terminals(block, owner_ref=None, owner_anchor_ea=0x1000)


@pytest.mark.parametrize("kind", (InsnKind.RET, InsnKind.GOTO))
def test_classifier_rejects_post_init_erased_raw_transfer_marker(kind: InsnKind) -> None:
    instruction = InsnSnapshot(0x42, 0x1000, (), kind=kind, raw_opcode=0x42)
    object.__setattr__(instruction, "control_transfer_kind", None)
    with pytest.raises(ValueError, match="requires control transfer"):
        classify_block_effects_and_terminals(
            _block(instruction, succs=(2,) if kind is InsnKind.GOTO else ()),
            owner_ref=None,
            owner_anchor_ea=0x1000,
        )


@pytest.mark.parametrize("kind", (InsnKind.NOP, InsnKind.STORE, InsnKind.CALL))
def test_classifier_rejects_foreign_transfer_marker(kind: InsnKind) -> None:
    instruction = InsnSnapshot(
        0x42, 0x1000, (), kind=kind, control_transfer_kind=ControlTransferKind.GOTO,
    )
    with pytest.raises(ValueError, match="must not carry control transfer"):
        classify_block_effects_and_terminals(
            _block(instruction), owner_ref=None, owner_anchor_ea=0x1000,
        )


@pytest.mark.parametrize("transfer", (ControlTransferKind.GOTO, ControlTransferKind.RETURN))
def test_classifier_accepts_unknown_kind_recovered_transfer(transfer: ControlTransferKind) -> None:
    instruction = InsnSnapshot(0x42, 0x1000, (), control_transfer_kind=transfer)
    classify_block_effects_and_terminals(
        _block(instruction), owner_ref=None, owner_anchor_ea=0x1000,
    )


def test_exact_claim_semantics_rejects_state_and_storage_forgery() -> None:
    from dataclasses import replace

    from tests.unit.transforms.unflatten_authority.test_bind import _exact_fixture

    _source, proposal, _exclusion, refs = _exact_fixture()
    claim = next(item for item in proposal.claims if item.kind.value == "exact_infeasible_effect")
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    assert validate_exact_effect_claim_semantics(
        proposal=proposal, claim=claim, source_serial_by_ref=serial_by_ref,
    ) is not None

    object.__setattr__(claim, "normalized_state", claim.normalized_state + 1)
    assert validate_exact_effect_claim_semantics(
        proposal=proposal, claim=claim, source_serial_by_ref=serial_by_ref,
    ) is None
    object.__setattr__(claim, "normalized_state", 7)
    object.__setattr__(claim, "state_identity", replace(claim.state_identity, offset=8))
    assert validate_exact_effect_claim_semantics(
        proposal=proposal, claim=claim, source_serial_by_ref=serial_by_ref,
    ) is None


def test_build_proposal_requires_explicit_route_selection_and_preserves_mixed_claims() -> None:
    """A canonical route present in the evidence is not an implicit allowance."""

    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture
    from d810.transforms.unflatten_authority import producer_api

    source, proposal, exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    common = dict(
        plan_id=proposal.plan_id,
        source=source,
        block_refs_by_serial=refs,
        source_generation=proposal.source_identity_catalog.generation,
        canonical_route_evidence=proposal.route_evidence,
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=proposal.use_def_witness,
    )
    with pytest.raises(ValueError, match="semantic route or exact effect"):
        producer_api.build_proposal(**common, exact_state_effect_exclusions=())

    route_only = producer_api.build_proposal(
        **common,
        selected_route_proof_ids=(proof.proof_id,),
        exact_state_effect_exclusions=(),
    )
    assert tuple(item.route_proof_ids for item in route_only.claims) == ((proof.proof_id,),)

    mixed = producer_api.build_proposal(
        **common,
        selected_route_proof_ids=(proof.proof_id,),
        exact_state_effect_exclusions=(exclusion,),
    )
    assert {item.kind.value for item in mixed.claims} == {
        "equivalent_semantic_route", "exact_infeasible_effect",
    }
    assert sum(bool(getattr(item, "route_proof_ids", ())) for item in mixed.claims) == 2


def test_route_adapters_select_one_canonical_proof_and_reject_ambiguity() -> None:
    """Emitter DTOs are selectors over sealed evidence, never new evidence."""

    from dataclasses import replace

    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition, TransitionProof,
    )
    from d810.analyses.control_flow.native_preanalysis_session import (
        BootstrapRouteEvidence, BootstrapRouteProofKind,
    )
    from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute
    from d810.transforms.minimal_unflatten_emit import (
        BootstrapEntryRouteForecast, ConcreteEntryRouteForecast,
        ConditionalEntryBridgeForecast,
    )
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    kwargs = dict(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=proposal.route_evidence,
    )
    selected_index = producer_api.TransitionRouteSelectionIndex.from_proofs(
        proposal.route_evidence.route_proofs,
    )


    with pytest.raises(ValueError, match="outside"):
        BootstrapRouteEvidence(
            refs[0].identity, 0xDEAD, 7, refs[2].identity, 0x3000,
            BootstrapRouteProofKind.STATIC_NATIVE,
        )

    bootstrap_row = BootstrapEntryRouteForecast(0, 2, 7, 0x1000, 0x3000)
    # A conditional canonical proof must not be reinterpreted as a bootstrap row.
    with pytest.raises(ValueError, match="zero"):
        producer_api.resolve_bootstrap_entry_route(
            bootstrap_row,
            source=source,
            source_catalog=proposal.source_identity_catalog,
            block_refs_by_serial=refs,
            selected_transitions=selected_index,
        )

    conditional = ConditionalEntryBridgeForecast(1, 0x2001, 3, 2, True)
    assert producer_api.adapt_conditional_entry_route(conditional, **kwargs) is proposal.route_evidence.route_proofs[0]
    with pytest.raises(ValueError, match="zero"):
        producer_api.adapt_conditional_entry_route(
            replace(conditional, predicate_ea=0xDEAD), **kwargs,
        )

    native = NativeBoundTransitionRoute("fact", 0x1000, 0, 7, 2)
    native_candidate = replace(
        proposal.route_evidence.route_proofs[0],
        diagnostic_provenance=(("fact_id", "fact"),),
    )
    from d810.analyses.control_flow.semantic_route_evidence import (
        canonical_semantic_evidence_from_proofs,
        SemanticRouteEvidenceRejected,
    )
    native_evidence = canonical_semantic_evidence_from_proofs(
        native_key=proposal.route_evidence.native_key,
        generation=proposal.route_evidence.generation,
        proofs=(native_candidate,),
    )
    # STATE_CHOICE is a conditional proof family, not the direct physical-entry
    # receipt consumed by NativeBoundTransitionRoute.
    with pytest.raises(ValueError, match="zero"):
        producer_api.adapt_native_bound_transition_route(
            native, **{**kwargs, "canonical_evidence": native_evidence},
        )
    transition = StateWriteTransition(
        0, 7, 2, False, None,
        proof=TransitionProof("test", "test", True),
    )
    with pytest.raises(ValueError, match="canonical typed fact"):
        producer_api.adapt_state_transition_route(
            transition, state_identity=proposal.plan_inputs.state_identity, **kwargs,
        )

    assert not hasattr(producer_api, "adapt_interval_route")

    duplicate = replace(
        proposal.route_evidence.route_proofs[0],
        source_owner_anchor_ea=0x1001,
    )
    with pytest.raises(SemanticRouteEvidenceRejected, match="divergent authoritative payload"):
        canonical_semantic_evidence_from_proofs(
            native_key=proposal.route_evidence.native_key,
            generation=proposal.route_evidence.generation,
            proofs=(proposal.route_evidence.route_proofs[0], duplicate),
        )


def test_state_transition_rejects_bootstrap_for_decision_dag_fact() -> None:
    """A coordinate match cannot reinterpret a DAG fact as bootstrap authority."""

    from dataclasses import replace
    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition, TransitionProof,
    )
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.analyses.control_flow.semantic_route_evidence import (
        DecisionDagRouteWitness, SemanticRouteFact, SemanticRouteFactKind,
    )
    from d810.analyses.control_flow.semantic_route_evidence import SemanticRouteProofKind
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    state = StorageIdentity(StorageIdentityKind.STACK, 4)
    fact = SemanticRouteFact(
        kind=SemanticRouteFactKind.DECISION_DAG,
        owner_serial=0,
        source_serial=1,
        source_instruction_ea=0x2000,
        state_constant=7,
        target_serial=2,
        owner_anchor_ea=0x1000,
        target_anchor_ea=0x3000,
        path_serials=(0, 1),
        path_edges=((0, 1),),
        decision_dag_witness=DecisionDagRouteWitness(
            state_identity=state,
            state_constant=7,
            entry_serial=1,
            entry_anchor_ea=0x2000,
            path_serials=(1,),
            path_anchors=(0x2000,),
            comparisons=tuple(DecisionDagComparisonWitness(serial, comparison, state) for serial, comparison in (
                (1, RouteComparison(1, "jz", 7, 2, 3)),
            )),
            aliases=(),
        ),
    )
    transition = StateWriteTransition(
        0, 7, 2, False, None,
        proof=TransitionProof("typed", "typed", True),
        semantic_route_fact=fact,
    )
    # Forge only the legacy proof classification; all stable coordinates still
    # match the transition. The typed matrix must reject it.
    old_kind = proof.proof_kind
    old_write = proof.state_write
    object.__setattr__(proof, "proof_kind", SemanticRouteProofKind.BOOTSTRAP)
    object.__setattr__(proof, "state_write", None)
    try:
        with pytest.raises(ValueError, match="bootstrap route"):
            producer_api.adapt_state_transition_route(
                transition,
                source=source,
                source_catalog=proposal.source_identity_catalog,
                block_refs_by_serial=refs,
                canonical_evidence=proposal.route_evidence,
                state_identity=state,
            )
    finally:
        object.__setattr__(proof, "proof_kind", old_kind)
        object.__setattr__(proof, "state_write", old_write)


def test_state_transition_selects_exact_guarded_physical_assignment() -> None:
    """A typed guarded DECISION_DAG fact selects its STATE_ASSIGNMENT proof."""

    from d810.analyses.control_flow.minimal_state_recovery import StateWriteTransition
    from d810.analyses.control_flow.semantic_route_evidence import (
        build_canonical_semantic_evidence,
    )
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.analyses.control_flow.test_semantic_route_evidence import (
        _guarded_alias_store_inputs,
    )

    source, fact, context, _branch, _store = _guarded_alias_store_inputs()
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is None and result.evidence is not None
    (proof,) = result.evidence.route_proofs
    refs = {
        serial: NativeBlockRef(identity)
        for serial, identity in context.identities_by_serial
    }
    catalog = producer_api.build_source_identity_catalog(
        source,
        refs,
        native_key=context.native_key,
        source_generation=context.generation,
    )
    route = StateWriteTransition(
        write_block=fact.owner_serial,
        next_state=fact.state_constant,
        target_handler=fact.target_serial,
        is_return=False,
        branch_arm=None,
        via_block=fact.source_serial,
        semantic_route_fact=fact,
        physical_state_write=fact.physical_state_write,
    )
    kwargs = dict(
        source=source,
        source_catalog=catalog,
        block_refs_by_serial=refs,
        canonical_evidence=result.evidence,
        state_identity=context.state_identity,
    )

    assert producer_api.adapt_state_transition_route(route, **kwargs) is proof

    physical = fact.physical_state_write
    assert physical is not None and physical.guarded_selection is not None
    for field, value in (
        ("write_block", fact.source_serial),
        ("via_block", fact.owner_serial),
        ("next_state", fact.state_constant + 1),
        ("target_handler", physical.guarded_selection.true_target_serial),
        ("physical_state_write", replace(physical, guarded_selection=None)),
    ):
        with pytest.raises(ValueError, match="zero or multiple canonical matches"):
            producer_api.adapt_state_transition_route(
                replace(route, **{field: value}),
                **kwargs,
            )

    witnessless = replace(
        fact,
        physical_state_write=replace(physical, guarded_selection=None),
    )
    with pytest.raises(ValueError, match="zero or multiple canonical matches"):
        producer_api.adapt_state_transition_route(
            replace(route, semantic_route_fact=witnessless),
            **kwargs,
        )

    drifted_guard = replace(
        physical.guarded_selection,
        selected_target_serial=physical.guarded_selection.true_target_serial,
        comparison_instruction=replace(
            physical.guarded_selection.comparison_instruction,
            branch_predicate=(
                PredicateKind.EQ
                if physical.guarded_selection.comparison_instruction.branch_predicate
                is PredicateKind.NE
                else PredicateKind.NE
            ),
        ),
    )
    mismatched = replace(
        fact,
        physical_state_write=replace(physical, guarded_selection=drifted_guard),
    )
    with pytest.raises(ValueError, match="zero or multiple canonical matches"):
        producer_api.adapt_state_transition_route(
            replace(route, semantic_route_fact=mismatched),
            **kwargs,
        )


def test_state_transition_selects_exact_split_physical_decision_dag_writer() -> None:
    """A delivery-block route binds its separately sealed physical writer."""

    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition,
    )
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.analyses.control_flow import semantic_route_evidence as route_evidence
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidenceProductionContext,
        DecisionDagRouteWitness,
        SemanticPhysicalStateWriteWitness,
        SemanticRouteFact,
        SemanticRouteFactKind,
        build_canonical_semantic_evidence,
    )
    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import FlowGraph
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.analyses.control_flow.test_semantic_route_evidence import (
        NATIVE_KEY,
        _block,
    )

    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    first_constant = 0x1AEA4348
    second_constant = 0x7EC4A11D

    def state_write(ea: int, constant: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=0,
            ea=ea,
            operands=(),
            l=MopSnapshot(
                kind=OperandKind.NUMBER, size=4, value=constant,
            ),
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
        control_transfer_kind=ControlTransferKind.GOTO,
        is_unconditional_jump=True,
    )
    comparison = InsnSnapshot(
        opcode=0,
        ea=0x1304,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        r=MopSnapshot(
            kind=OperandKind.NUMBER, size=4, value=first_constant,
        ),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=47),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            70: replace(
                _block(70, 0x1700, succs=(71,), preds=()),
                insn_snapshots=(first_write,),
            ),
            72: replace(
                _block(72, 0x1720, succs=(71,), preds=()),
                insn_snapshots=(second_write,),
            ),
            71: replace(
                _block(71, 0x1730, succs=(3,), preds=(70, 72)),
                insn_snapshots=(delivery,),
            ),
            3: replace(
                _block(3, 0x1300, succs=(47, 48), preds=(71,)),
                insn_snapshots=(comparison,),
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

    def route_fact(
        writer_serial: int,
        write: InsnSnapshot,
        constant: int,
        target_serial: int,
        *,
        delivery_owned: bool = False,
    ) -> SemanticRouteFact:
        physical = SemanticPhysicalStateWriteWitness(
            route_evidence._instruction_projection(write),
            state,
            4,
            constant,
            source_serial=writer_serial,
        )
        return SemanticRouteFact(
            SemanticRouteFactKind.DECISION_DAG,
            71 if delivery_owned else writer_serial,
            71,
            0x1730,
            constant,
            target_serial,
            0x1730 if delivery_owned else int(write.ea),
            int(graph.blocks[target_serial].start_ea),
            (71,) if delivery_owned else (writer_serial, 71),
            () if delivery_owned else ((writer_serial, 71),),
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
            physical_state_write=physical,
        )

    first_fact = route_fact(70, first_write, first_constant, 47)
    second_fact = route_fact(72, second_write, second_constant, 48)
    transition_fact = route_fact(
        70, first_write, first_constant, 47, delivery_owned=True,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:split-physical-dag-adapter",
        state,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    result = build_canonical_semantic_evidence(
        (first_fact, second_fact), context,
    )
    assert result.abstention is None and result.evidence is not None
    refs = {
        serial: NativeBlockRef(identity)
        for serial, identity in identities.items()
    }
    catalog = producer_api.build_source_identity_catalog(
        graph,
        refs,
        native_key=NATIVE_KEY,
        source_generation=1,
    )
    route = StateWriteTransition(
        write_block=71,
        next_state=first_constant,
        target_handler=47,
        is_return=False,
        branch_arm=None,
        via_block=None,
        semantic_route_fact=transition_fact,
        physical_state_write=transition_fact.physical_state_write,
    )
    kwargs = dict(
        source=graph,
        source_catalog=catalog,
        block_refs_by_serial=refs,
        canonical_evidence=result.evidence,
        state_identity=state,
    )

    selected = producer_api.adapt_state_transition_route(route, **kwargs)
    assert selected.source_identity == refs[71].identity
    assert selected.source_owner_identity == refs[70].identity
    assert selected.state_write is not None
    assert selected.state_write.identity == refs[70].identity
    assert selected.state_write.physical_state_write is first_fact.physical_state_write

    for field, value in (
        ("write_block", 70),
        ("physical_state_write", second_fact.physical_state_write),
    ):
        with pytest.raises(ValueError, match="zero or multiple canonical matches"):
            producer_api.adapt_state_transition_route(
                replace(route, **{field: value}), **kwargs,
            )

    nonreciprocal = replace(
        graph,
        blocks={
            **graph.blocks,
            71: replace(graph.blocks[71], preds=(72,)),
        },
    )
    with pytest.raises(ValueError, match="zero or multiple canonical matches"):
        producer_api.adapt_state_transition_route(
            route, **{**kwargs, "source": nonreciprocal},
        )

    wrong_delivery = replace(
        delivery,
        l=replace(delivery.l, block_ref=48),
    )
    stale_goto_target = replace(
        graph,
        blocks={
            **graph.blocks,
            71: replace(
                graph.blocks[71],
                insn_snapshots=(wrong_delivery,),
            ),
        },
    )
    with pytest.raises(ValueError, match="zero or multiple canonical matches"):
        producer_api.adapt_state_transition_route(
            route, **{**kwargs, "source": stale_goto_target},
        )

    wrong_target_graph = replace(
        graph,
        blocks={
            **graph.blocks,
            71: replace(
                graph.blocks[71],
                succs=(48,),
                insn_snapshots=(wrong_delivery,),
            ),
            3: replace(graph.blocks[3], preds=()),
            48: replace(graph.blocks[48], preds=(3, 71)),
        },
    )
    wrong_identities = {
        serial: route_evidence.stable_block_identity_from_snapshot(
            block, native_key=NATIVE_KEY,
        )
        for serial, block in wrong_target_graph.blocks.items()
    }
    assert all(identity is not None for identity in wrong_identities.values())
    wrong_context = replace(
        context,
        atomic_group_id="canonical-semantic:wrong-delivery-target",
        blocks=tuple(wrong_target_graph.blocks.values()),
        identities_by_serial=tuple(wrong_identities.items()),
    )
    wrong_result = build_canonical_semantic_evidence(
        (first_fact, second_fact), wrong_context,
    )
    # The supplied fact corpus still claims delivery -> blk47, whereas this
    # graph's sealed delivery edge reaches blk48.  Canonical production must
    # reject that stale corpus before an adapter is allowed to consume it.
    assert wrong_result.evidence is None
    assert wrong_result.abstention is not None
    assert (
        wrong_result.abstention.reason
        is route_evidence.CanonicalSemanticEvidenceProductionReason.DECISION_DAG_PATH_SHAPE
    )


def test_state_transition_selects_exact_direct_physical_decision_dag_writer() -> None:
    """A same-block physical MOV retains direct canonical owner semantics."""

    from d810.analyses.control_flow.minimal_state_recovery import StateWriteTransition
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.analyses.control_flow import semantic_route_evidence as route_evidence
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidenceProductionContext,
        DecisionDagRouteWitness,
        SemanticPhysicalStateWriteWitness,
        SemanticRouteFact,
        SemanticRouteFactKind,
        build_canonical_semantic_evidence,
    )
    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import FlowGraph
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.analyses.control_flow.test_semantic_route_evidence import (
        NATIVE_KEY,
        _block,
    )

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
    comparison = InsnSnapshot(
        opcode=0,
        ea=0x1300,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=constant),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=47),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            70: replace(
                _block(70, 0x1700, succs=(3,), preds=()),
                insn_snapshots=(write,),
            ),
            3: replace(
                _block(3, 0x1300, succs=(47, 48), preds=(70,)),
                insn_snapshots=(comparison,),
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
    physical = SemanticPhysicalStateWriteWitness(
        route_evidence._instruction_projection(write),
        state,
        4,
        constant,
        source_serial=70,
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        70,
        70,
        0x1704,
        constant,
        47,
        0x1704,
        0x1470,
        (70,),
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
        physical_state_write=physical,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:direct-physical-dag-adapter",
        state,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is None and result.evidence is not None
    refs = {
        serial: NativeBlockRef(identity)
        for serial, identity in identities.items()
    }
    catalog = producer_api.build_source_identity_catalog(
        graph, refs, native_key=NATIVE_KEY, source_generation=1,
    )
    route = StateWriteTransition(
        write_block=70,
        next_state=constant,
        target_handler=47,
        is_return=False,
        branch_arm=None,
        via_block=None,
        semantic_route_fact=fact,
        physical_state_write=physical,
    )
    kwargs = dict(
        source=graph,
        source_catalog=catalog,
        block_refs_by_serial=refs,
        canonical_evidence=result.evidence,
        state_identity=state,
    )

    selected = producer_api.adapt_state_transition_route(route, **kwargs)
    assert selected.source_identity == refs[70].identity
    assert selected.source_owner_identity is None
    assert selected.state_write is not None
    assert selected.state_write.identity == refs[70].identity
    assert selected.state_write.physical_state_write == physical

    with pytest.raises(ValueError, match="zero or multiple canonical matches"):
        producer_api.adapt_state_transition_route(
            replace(route, physical_state_write=None), **kwargs,
        )

    owner_graph = replace(
        graph,
        blocks={
            **graph.blocks,
            69: _block(69, 0x1690, succs=(70,), preds=()),
            70: replace(graph.blocks[70], preds=(69,)),
        },
        entry_serial=69,
    )
    owner_identities = {
        serial: route_evidence.stable_block_identity_from_snapshot(
            block, native_key=NATIVE_KEY,
        )
        for serial, block in owner_graph.blocks.items()
    }
    assert all(identity is not None for identity in owner_identities.values())
    owner_fact = replace(
        fact,
        owner_serial=69,
        owner_anchor_ea=0x1690,
        path_serials=(69, 70),
        path_edges=((69, 70),),
    )
    owner_context = replace(
        context,
        atomic_group_id="canonical-semantic:owned-direct-physical-dag-adapter",
        blocks=tuple(owner_graph.blocks.values()),
        identities_by_serial=tuple(owner_identities.items()),
    )
    owner_result = build_canonical_semantic_evidence((owner_fact,), owner_context)
    assert owner_result.abstention is None and owner_result.evidence is not None
    owner_refs = {
        serial: NativeBlockRef(identity)
        for serial, identity in owner_identities.items()
    }
    owner_catalog = producer_api.build_source_identity_catalog(
        owner_graph, owner_refs, native_key=NATIVE_KEY, source_generation=1,
    )
    owner_route = replace(
        route,
        write_block=69,
        via_block=70,
        semantic_route_fact=owner_fact,
    )
    owner_selected = producer_api.adapt_state_transition_route(
        owner_route,
        source=owner_graph,
        source_catalog=owner_catalog,
        block_refs_by_serial=owner_refs,
        canonical_evidence=owner_result.evidence,
        state_identity=state,
    )
    assert owner_selected.source_identity == owner_refs[70].identity
    assert owner_selected.source_owner_identity == owner_refs[69].identity


@pytest.mark.parametrize(
    ("adapter", "route"),
    (
        (
            producer_module.resolve_bootstrap_entry_route,
            _ForeignBootstrapEntryRouteForecast(0, 2, 7, 0x1000, 0x3000),
        ),
        (
            producer_module.adapt_conditional_entry_route,
            _ForeignConditionalEntryBridgeForecast(1, 0x2001, 3, 2, True),
        ),
    ),
)
def test_route_adapters_reject_noncanonical_forecast_instances(adapter, route) -> None:
    """Adapters accept only the exact canonical forecast DTO classes."""

    with pytest.raises(TypeError, match="Forecast"):
        if adapter is producer_module.resolve_bootstrap_entry_route:
            adapter(
                route,
                source=None,
                source_catalog=None,
                block_refs_by_serial={},
                selected_transitions=None,
            )
        else:
            adapter(
                route,
                source=None,
                source_catalog=None,
                block_refs_by_serial={},
                canonical_evidence=None,
            )


def test_route_adapters_reject_semantic_field_drift_beyond_endpoint_coincidence() -> None:
    """Selectors must bind the whole proof, not merely one matching endpoint."""

    from dataclasses import replace

    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition, TransitionProof,
    )
    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticEdgeRole, SemanticRouteProofKind, SemanticRouteShape,
    )
    from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute
    from d810.transforms.minimal_unflatten_emit import (
        ConcreteEntryRouteForecast, ConditionalEntryBridgeForecast,
    )
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    kwargs = dict(source=source, source_catalog=proposal.source_identity_catalog,
                  block_refs_by_serial=refs, canonical_evidence=proposal.route_evidence)
    conditional = ConditionalEntryBridgeForecast(1, 0x2001, 3, 2, True)
    native = NativeBoundTransitionRoute("fact", 0x1000, 0, 7, 2)
    transition = StateWriteTransition(
        0, 7, 2, False, None,
        proof=TransitionProof("test", "test", True),
    )

    unbound_drift: list[str] = []

    def proof_drift(field: str, value: object, invoke) -> None:
        original = getattr(proof, field)
        object.__setattr__(proof, field, value)
        try:
            try:
                invoke()
            except (TypeError, ValueError):
                return
            unbound_drift.append(field)
        finally:
            object.__setattr__(proof, field, original)

    proof_drift("proof_kind", SemanticRouteProofKind.BOOTSTRAP,
                lambda: producer_api.adapt_conditional_entry_route(conditional, **kwargs))
    proof_drift("shape", SemanticRouteShape.DIRECT,
                lambda: producer_api.adapt_conditional_entry_route(conditional, **kwargs))
    proof_drift("source_identity", refs[0].identity,
                lambda: producer_api.adapt_conditional_entry_route(conditional, **kwargs))
    proof_drift("source_anchor_ea", 0xDEAD,
                lambda: producer_api.adapt_conditional_entry_route(conditional, **kwargs))
    destination = proof.destinations[0]
    old_destination = (destination.target_identity, destination.target_anchor_ea, destination.role, destination.state_constant)
    for field, value in (("target_identity", refs[0].identity), ("target_anchor_ea", 0xDEAD),
                         ("role", SemanticEdgeRole.DIRECT), ("state_constant", 0x100000007)):
        index = ("target_identity", "target_anchor_ea", "role", "state_constant").index(field)
        object.__setattr__(destination, field, value)
        try:
            try:
                producer_api.adapt_conditional_entry_route(conditional, **kwargs)
            except (TypeError, ValueError):
                pass
            else:
                unbound_drift.append(f"destination.{field}")
        finally:
            object.__setattr__(destination, field, old_destination[index])

    state_write = proof.state_write
    assert state_write is not None
    old_write = (state_write.identity, state_write.state_constant, state_write.width, state_write.instruction_ea)
    for field, value in (("identity", refs[2].identity), ("state_constant", 8),
                         ("width", 8), ("instruction_ea", 0xDEAD)):
        index = ("identity", "state_constant", "width", "instruction_ea").index(field)
        object.__setattr__(state_write, field, value)
        try:
            try:
                producer_api.adapt_native_bound_transition_route(native, **kwargs)
            except (TypeError, ValueError):
                pass
            else:
                unbound_drift.append(f"state_write.{field}")
        finally:
            object.__setattr__(state_write, field, old_write[index])

    # The DTO label remains non-authoritative, but a STATE_CHOICE proof cannot
    # be reclassified as the physical-entry STATE_ASSIGNMENT receipt.
    with pytest.raises(ValueError, match="zero"):
        producer_api.adapt_native_bound_transition_route(
            replace(native, fact_id="foreign"), **kwargs,
        )

    try:
        producer_api.adapt_state_transition_route(
            replace(transition, next_state=0x100000007),
            state_identity=proposal.plan_inputs.state_identity,
            **kwargs,
        )
    except (TypeError, ValueError):
        pass
    else:
        unbound_drift.append("state_transition.next_state_width")
    with pytest.raises(ValueError, match="canonical typed fact"):
        producer_api.adapt_state_transition_route(
            replace(transition, via_block=1, preserve_via_block=True),
            state_identity=proposal.plan_inputs.state_identity,
            **kwargs,
        )
    for field, value in (
        ("proof", None), ("via_block", 0), ("branch_arm", 1),
        ("preserve_via_block", True), ("proof", object()),
        ("proof", replace(transition.proof, trusted=False)),
    ):
        try:
            producer_api.adapt_state_transition_route(
                replace(transition, **{field: value}),
                state_identity=proposal.plan_inputs.state_identity,
                **kwargs,
            )
        except (TypeError, ValueError):
            pass
        else:
            unbound_drift.append(f"state_transition.{field}")
    try:
        producer_api.adapt_state_transition_route(
            transition,
            state_identity=replace(
                proposal.plan_inputs.state_identity,
                offset=proposal.plan_inputs.state_identity.offset + 1,
            ),
            **kwargs,
        )
    except (TypeError, ValueError):
        pass
    else:
        unbound_drift.append("state_transition.state_identity")
    assert not unbound_drift, f"semantic drift accepted by adapters: {unbound_drift}"


def test_state_transition_preserve_via_block_requires_canonical_preservation_relation() -> None:
    """A producer-only clone flag must not reuse an otherwise identical route proof."""

    from dataclasses import replace
    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition, TransitionProof,
    )
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    kwargs = dict(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=proposal.route_evidence,
        state_identity=proposal.plan_inputs.state_identity,
    )
    transition = StateWriteTransition(
        0, 7, 2, False, None, via_block=1,
        proof=TransitionProof("test", "test", True),
    )
    with pytest.raises(ValueError, match="canonical typed fact"):
        producer_api.adapt_state_transition_route(transition, **kwargs)
    with pytest.raises(ValueError, match="canonical typed fact"):
        producer_api.adapt_state_transition_route(
            replace(transition, preserve_via_block=True), **kwargs,
        )


@pytest.mark.parametrize("logical_sibling", (False, True), ids=("native", "logical-exit"))
def test_bootstrap_transition_selects_actual_recovery_fact_and_entry_view(
    logical_sibling: bool,
) -> None:
    """Bootstrap entry selection must consume the transition-owned fact."""

    import copy
    from dataclasses import replace
    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition,
        _DecisionDagStateRoute,
        _bootstrap_semantic_route_fact_for_transition,
    )
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidenceProductionContext,
        SemanticDagEndpointKind,
        SemanticLogicalDagEndpoint,
        SemanticPhysicalStateWriteWitness,
        SemanticRouteFact,
        SemanticRouteFactKind,
        build_canonical_semantic_evidence,
        canonical_semantic_evidence_from_proofs,
    )
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.analyses.control_flow.semantic_route_evidence import SemanticDagNamespaceBridge
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.expressions import ValueOpKind
    from d810.ir.graph_fingerprint import _instruction_projection
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
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
    from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute
    from d810.transforms.unflatten_authority import producer_api

    key = NativePreanalysisKey("bootstrap", "x86", 64, 0, "a" * 64, "b" * 64, "c" * 64)
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    def block(serial, start_ea, succs, preds, instructions=(), kind=None):
        return BlockSnapshot(
            serial=serial,
            block_type=len(succs),
            succs=succs,
            preds=preds,
            flags=0,
            start_ea=start_ea,
            insn_snapshots=tuple(instructions),
            tail_opcode=instructions[-1].opcode if instructions else None,
            kind=kind or (BlockKind.ONE_WAY if succs else BlockKind.ZERO_WAY),
            tail_kind=instructions[-1].kind if instructions else None,
            raw_tail_opcode=instructions[-1].raw_opcode if instructions else None,
        )

    source_write = InsnSnapshot(
        opcode=0,
        ea=0x1100,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    branch = InsnSnapshot(
        opcode=0,
        ea=0x1600,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=7),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            0: block(0, 0x1000, (1,), (), kind=BlockKind.ONE_WAY),
            1: block(1, 0x1100, (3,), (0,), (source_write,)),
            3: block(3, 0x1300, (5,), (1,)),
            5: replace(
                block(
                    5,
                    0x1500,
                    (6,),
                    (3,),
                    (InsnSnapshot(opcode=0, ea=0x1508, operands=(), kind=InsnKind.NOP),),
                ),
                native_start_ea=0x1500,
            ),
            6: block(6, 0x1600, (7, 11), (5,), (branch,), kind=BlockKind.TWO_WAY),
            7: block(
                7,
                0x1700,
                (),
                (6,),
                (InsnSnapshot(opcode=0, ea=0x1700, operands=(), kind=InsnKind.NOP),),
            ),
            11: block(
                11,
                0xFFFFFFFFFFFFFFFF if logical_sibling else 0x1B00,
                (),
                (6,),
                kind=BlockKind.ZERO_WAY,
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    refs = {
        serial: NativeBlockRef(
            StableBlockIdentity.from_intervals(
                (NativeEaInterval(int(block.start_ea), int(block.start_ea) + 0x20),),
                native_key=key,
                exact_instruction_eas=tuple(int(item.ea) for item in block.insn_snapshots),
            )
        )
        for serial, block in graph.blocks.items()
    }
    if logical_sibling:
        refs[11] = LogicalBlockRef("bootstrap-logical-exit", "function-exit", 0)
    source_catalog = producer_api.build_source_identity_catalog(
        graph, refs, native_key=key, source_generation=1,
    )
    dag_route = _DecisionDagStateRoute(
        target=7,
        certified_targets=frozenset({7}),
        entry_serial=6,
        path_serials=(6,),
        path_anchors=(0x1600,),
            comparisons=(DecisionDagComparisonWitness(6, RouteComparison(6, "jz", 7, 7, 11), state_identity),),
    )
    transition = StateWriteTransition(5, 7, 7, False, None)
    fact = _bootstrap_semantic_route_fact_for_transition(
        transition,
        dag_route,
        graph,
        state_identity=state_identity,
    )
    assert fact is not None
    assert fact.kind is SemanticRouteFactKind.BOOTSTRAP
    assert fact.target_anchor_ea == 0x1700
    fact = replace(fact, fact_id="bootstrap:owned")
    context = CanonicalSemanticEvidenceProductionContext(
        key,
        1,
        "bootstrap-owner",
        state_identity,
        tuple(graph.blocks.values()),
        tuple(
            (serial, ref.identity)
            for serial, ref in refs.items()
            if type(ref) is NativeBlockRef
        ),
        logical_endpoints_by_serial=(
            ((
                11,
                SemanticLogicalDagEndpoint(
                    SemanticDagEndpointKind.FUNCTION_EXIT,
                    11,
                    "bootstrap-logical-exit",
                    "function-exit",
                    0,
                ),
            ),)
            if logical_sibling else ()
        ),
        entry_serial=0,
    )
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is None and result.evidence is not None
    proof = result.evidence.route_proofs[0]
    assert proof.proof_id.startswith("sha256:")
    assert ("fact_id", fact.fact_id) in proof.diagnostic_provenance
    unlabeled = build_canonical_semantic_evidence(
        (replace(fact, fact_id=None),), replace(
            context, atomic_group_id="human-label-that-must-not-matter",
        ),
    )
    assert unlabeled.evidence is not None
    assert unlabeled.evidence.atomic_group_id == result.evidence.atomic_group_id
    assert unlabeled.evidence.route_proofs[0].proof_id == proof.proof_id
    assert not any(
        name == "fact_id"
        for name, _value in unlabeled.evidence.route_proofs[0].diagnostic_provenance
    )
    duplicate = build_canonical_semantic_evidence((fact, fact), context)
    assert duplicate.abstention is None and duplicate.evidence is not None
    assert len(duplicate.evidence.route_proofs) == 1
    assert duplicate.evidence.atomic_group_id == result.evidence.atomic_group_id
    assert duplicate.evidence.route_proofs[0].proof_id == proof.proof_id
    kwargs = dict(
        source=graph,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=result.evidence,
        state_identity=state_identity,
    )
    selected = producer_api.TransitionRouteSelectionIndex.from_proofs((proof,))
    selected_proof = producer_api.adapt_state_transition_route(
        replace(transition, semantic_route_fact=fact), **kwargs,
    )
    assert selected_proof is proof
    assert producer_api.adapt_state_transition_route(
        replace(
            transition,
            semantic_route_fact=replace(fact, fact_id="bootstrap:other-label"),
        ),
        **kwargs,
    ) is proof
    state_dag = proof.state_dag
    assert state_dag is not None
    canonical_dag = state_dag.witness
    (canonical_comparison,) = canonical_dag.comparisons
    for drifted_dag in (
        replace(
            canonical_dag,
            comparisons=(replace(
                canonical_comparison,
                state_identity=StorageIdentity(StorageIdentityKind.REGISTER, 6),
            ),),
        ),
        replace(
            canonical_dag,
            bridges=(SemanticDagNamespaceBridge(
                canonical_comparison.node, 0x1600, state_identity,
                StorageIdentity(StorageIdentityKind.REGISTER, 6), 4, 8,
            ),),
        ),
    ):
        drifted_evidence = canonical_semantic_evidence_from_proofs(
            result.evidence.native_key,
            result.evidence.generation,
            (replace(
                proof,
                state_dag=replace(state_dag, witness=drifted_dag),
                bootstrap=replace(
                    proof.bootstrap,
                    state_dag=replace(state_dag, witness=drifted_dag),
                ),
            ),),
        )
        with pytest.raises(ValueError, match="zero or multiple canonical matches"):
            producer_api.adapt_state_transition_route(
                replace(transition, semantic_route_fact=fact),
                **{**kwargs, "canonical_evidence": drifted_evidence},
            )
    if logical_sibling:
        drifted_dag = replace(
            fact.decision_dag_witness,
            comparisons=(DecisionDagComparisonWitness(6, RouteComparison(6, "jz", 7, 7, 7), state_identity),),
        )
        with pytest.raises(ValueError, match="zero or multiple canonical matches"):
            producer_api.adapt_state_transition_route(
                replace(
                    transition,
                    semantic_route_fact=replace(
                        fact,
                        decision_dag_witness=drifted_dag,
                        bootstrap_witness=replace(
                            fact.bootstrap_witness,
                            decision_dag_witness=drifted_dag,
                        ),
                    ),
                ),
                **kwargs,
            )
    forecast = BootstrapEntryRouteForecast(1, 7, 7, 0x1100, 0x1700)
    assert producer_api.resolve_bootstrap_entry_route(
        forecast,
        source=graph,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        selected_transitions=selected,
    ) is proof

    # The same physical entry may have two valid canonical views.  Its native
    # receipt consumes the direct STATE_ASSIGNMENT view; the BOOTSTRAP view is
    # reserved for resolve_bootstrap_entry_route below.
    native_fact = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND,
        fact.source_serial,
        fact.source_serial,
        fact.source_instruction_ea,
        fact.state_constant,
        fact.target_serial,
        fact.source_instruction_ea,
        fact.target_anchor_ea,
        (fact.source_serial,),
            (),
            fact_id="native-bound:physical-entry",
            physical_state_write=SemanticPhysicalStateWriteWitness(
                _instruction_projection(source_write), state_identity, 4, fact.state_constant,
            ),
        )
    mixed = build_canonical_semantic_evidence((native_fact, fact), context)
    assert mixed.abstention is None and mixed.evidence is not None
    assignment = next(
        item
        for item in mixed.evidence.route_proofs
        if item.proof_kind.name == "STATE_ASSIGNMENT"
    )
    native_route = NativeBoundTransitionRoute(
        "physical-entry",
        fact.source_instruction_ea,
        fact.source_serial,
        fact.state_constant,
        fact.target_serial,
    )
    assert producer_api.adapt_native_bound_transition_route(
        native_route,
        source=graph,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=mixed.evidence,
    ) is assignment

    # Native receipt provenance stays at 0x1100 even when a typed physical
    # state MOV is later in the same source block.  The adapter selects by the
    # receipt/source anchor; canonical binding owns the physical write replay.
    separate_write = replace(
        assignment.state_write,
        instruction_ea=0x1104,
        corridor_instruction_eas=(0x1104,),
        physical_state_write=None,
    )
    separate_assignment = replace(assignment, state_write=separate_write)
    separate_evidence = canonical_semantic_evidence_from_proofs(
        mixed.evidence.native_key,
        mixed.evidence.generation,
        (separate_assignment,),
    )
    assert producer_api.adapt_native_bound_transition_route(
        native_route,
        source=graph,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=separate_evidence,
    ).source_anchor_ea == native_route.source_instruction_ea
    with pytest.raises(ValueError, match="zero"):
        producer_api.adapt_native_bound_transition_route(
            replace(native_route, source_instruction_ea=0x1104),
            source=graph,
            source_catalog=source_catalog,
            block_refs_by_serial=refs,
            canonical_evidence=separate_evidence,
        )

    with pytest.raises(ValueError, match="zero"):
        producer_api.adapt_native_bound_transition_route(
            native_route,
            source=graph,
            source_catalog=source_catalog,
            block_refs_by_serial=refs,
            canonical_evidence=result.evidence,
        )

    duplicate_assignment = replace(
        assignment,
        proof_id="physical-entry:alternate-assignment",
        delivery_region=NativeEaInterval(0x1100, 0x1101),
    )
    ambiguous = canonical_semantic_evidence_from_proofs(
        mixed.evidence.native_key,
        mixed.evidence.generation,
        (assignment, duplicate_assignment),
    )
    with pytest.raises(ValueError, match="multiple"):
        producer_api.adapt_native_bound_transition_route(
            native_route,
            source=graph,
            source_catalog=source_catalog,
            block_refs_by_serial=refs,
            canonical_evidence=ambiguous,
        )

    key = producer_api.TransitionRouteSelectionKey(
        *producer_api.bootstrap_entry_route_key(
            forecast,
            source=graph,
            source_catalog=source_catalog,
            block_refs_by_serial=refs,
        )
    )
    assert len(selected.candidates(key)) == 1
    with pytest.raises(ValueError, match="zero"):
        producer_api.resolve_bootstrap_entry_route(
            replace(forecast, source_anchor_ea=0xDEAD),
            source=graph,
            source_catalog=source_catalog,
            block_refs_by_serial=refs,
            selected_transitions=selected,
        )
    duplicate = replace(proof, proof_id="bootstrap:duplicate")
    duplicate_index = producer_api.TransitionRouteSelectionIndex.from_proofs(
        (proof, duplicate),
    )
    assert len(duplicate_index.candidates(key)) == 2
    with pytest.raises(ValueError, match="multiple"):
        producer_api.resolve_bootstrap_entry_route(
            forecast,
            source=graph,
            source_catalog=source_catalog,
            block_refs_by_serial=refs,
            selected_transitions=duplicate_index,
        )

    def forged_fact(**fields):
        forged = copy.copy(fact)
        for field, value in fields.items():
            object.__setattr__(forged, field, value)
        return forged

    for field, value in (
        ("owner_serial", 3),
        ("source_instruction_ea", 0x1101),
        ("owner_anchor_ea", 0x1508),
        ("state_constant", 8),
        ("target_serial", 11),
    ):
        with pytest.raises(ValueError):
            producer_api.adapt_state_transition_route(
                replace(
                    transition,
                    semantic_route_fact=forged_fact(**{field: value}),
                ),
                **kwargs,
            )

    forged_bootstrap = copy.copy(fact.bootstrap_witness)
    assert forged_bootstrap is not None
    object.__setattr__(
        forged_bootstrap,
        "state_identity",
        StorageIdentity(StorageIdentityKind.STACK, 0x48),
    )
    forged = forged_fact(bootstrap_witness=forged_bootstrap)
    with pytest.raises(ValueError):
        producer_api.adapt_state_transition_route(
            replace(transition, semantic_route_fact=forged),
            **kwargs,
        )

    def proof_drift(field: str, value: object) -> None:
        original = getattr(proof, field)
        object.__setattr__(proof, field, value)
        try:
            with pytest.raises(ValueError):
                producer_api.adapt_state_transition_route(
                    replace(transition, semantic_route_fact=fact),
                    **kwargs,
                )
        finally:
            object.__setattr__(proof, field, original)

    proof_drift("source_anchor_ea", 0xDEAD)
    proof_drift("source_identity", refs[3].identity)
    state_write = proof.state_write
    assert state_write is not None
    original_write = (
        state_write.identity,
        state_write.instruction_ea,
        state_write.state_constant,
        state_write.width,
    )
    for field, value in (
        ("identity", refs[3].identity),
        ("instruction_ea", 0xDEAD),
        ("state_constant", 8),
        ("width", 8),
    ):
        index = ("identity", "instruction_ea", "state_constant", "width").index(field)
        object.__setattr__(state_write, field, value)
        try:
            with pytest.raises(ValueError):
                producer_api.adapt_state_transition_route(
                    replace(transition, semantic_route_fact=fact),
                    **kwargs,
                )
        finally:
            object.__setattr__(state_write, field, original_write[index])

    state_dag = proof.state_dag
    assert state_dag is not None
    original_dag = (
        state_dag.source_identity,
        state_dag.source_anchor_ea,
        state_dag.target_identity,
        state_dag.target_anchor_ea,
    )
    for field, value in (
        ("source_identity", refs[3].identity),
        ("source_anchor_ea", 0xDEAD),
        ("target_identity", refs[3].identity),
        ("target_anchor_ea", 0xDEAD),
    ):
        index = (
            "source_identity", "source_anchor_ea",
            "target_identity", "target_anchor_ea",
        ).index(field)
        object.__setattr__(state_dag, field, value)
        try:
            with pytest.raises(ValueError):
                producer_api.adapt_state_transition_route(
                    replace(transition, semantic_route_fact=fact),
                    **kwargs,
                )
        finally:
            object.__setattr__(state_dag, field, original_dag[index])

    dag_witness = state_dag.witness
    original_dag_state = dag_witness.state_constant
    object.__setattr__(dag_witness, "state_constant", 8)
    try:
        with pytest.raises(ValueError):
            producer_api.adapt_state_transition_route(
                replace(transition, semantic_route_fact=fact),
                **kwargs,
            )
    finally:
        object.__setattr__(dag_witness, "state_constant", original_dag_state)

    forged_dag = copy.copy(fact.bootstrap_witness.decision_dag_witness)
    object.__setattr__(forged_dag, "state_constant", 8)
    object.__setattr__(forged_bootstrap, "decision_dag_witness", forged_dag)
    with pytest.raises(ValueError):
        producer_api.adapt_state_transition_route(
            replace(transition, semantic_route_fact=forged_fact(bootstrap_witness=forged_bootstrap)),
            **kwargs,
        )

    destination = proof.destinations[0]
    original_destination = (destination.target_identity, destination.target_anchor_ea)
    for field, value in (("target_identity", refs[3].identity), ("target_anchor_ea", 0xDEAD)):
        index = ("target_identity", "target_anchor_ea").index(field)
        object.__setattr__(destination, field, value)
        try:
            with pytest.raises(ValueError):
                producer_api.adapt_state_transition_route(
                    replace(transition, semantic_route_fact=fact),
                    **kwargs,
                )
        finally:
            object.__setattr__(destination, field, original_destination[index])


def test_bootstrap_adapter_selects_canonical_proof_and_never_mints_authority() -> None:
    from d810.transforms.unflatten_authority import producer_api

    assert not hasattr(producer_api, "adapt_bootstrap_entry_route")


def test_state_partition_adapter_requires_exact_dag_namespaces_and_xdu_bridges() -> None:
    """Partition selection replays each typed DAG namespace and XDU bridge."""

    from d810.analyses.control_flow.minimal_state_recovery import StateWriteTransition
    from d810.analyses.control_flow.route_comparison import ExactU32XduNamespaceBridge
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.analyses.control_flow.semantic_route_evidence import (
        DecisionDagComparisonWitness,
        DecisionDagRouteWitness,
        SemanticDagNamespaceBridge,
        SemanticRouteFact,
        SemanticRouteFactKind,
        StatePartitionGroupWitness,
        StatePartitionMemberWitness,
        canonical_semantic_evidence_from_proofs,
    )
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import NativeBlockRef
    from tests.unit.analyses.control_flow.test_semantic_route_evidence import (
        NATIVE_KEY,
        _composite_partition_evidence,
        _identity,
    )

    source, base_evidence = _composite_partition_evidence()
    source = replace(
        source,
        blocks={
            **source.blocks,
            4: replace(
                source.blocks[4],
                insn_snapshots=(InsnSnapshot(0, 0x1400, (), kind=InsnKind.NOP),),
            ),
            6: replace(
                source.blocks[6],
                insn_snapshots=(InsnSnapshot(0, 0x1600, (), kind=InsnKind.NOP),),
            ),
        },
    )
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    register = StorageIdentity(StorageIdentityKind.REGISTER, 6)
    raw_bridge = ExactU32XduNamespaceBridge(5, 0x1500, 0x1500, state, register, 4, 8)
    proof = base_evidence.route_proofs[0]
    assert proof.state_dag is not None
    canonical_bridge = SemanticDagNamespaceBridge(
        proof.state_dag.witness.entry,
        raw_bridge.instruction_ea,
        raw_bridge.source_identity,
        raw_bridge.result_identity,
        raw_bridge.source_width,
        raw_bridge.result_width,
    )
    proof = replace(
        proof,
        state_dag=replace(
            proof.state_dag,
            witness=replace(proof.state_dag.witness, bridges=(canonical_bridge,)),
        ),
    )
    evidence = canonical_semantic_evidence_from_proofs(
        base_evidence.native_key, base_evidence.generation, (proof,),
    )
    canonical_proof = evidence.route_proofs[0]
    refs = {
        serial: NativeBlockRef(_identity(int(block.start_ea)))
        for serial, block in source.blocks.items()
    }
    catalog = producer_module.build_source_identity_catalog(
        source, refs, native_key=NATIVE_KEY, source_generation=evidence.generation,
    )
    group = StatePartitionGroupWitness(
        "partition-adapter-xdu", 2, 0x1200, state,
        (StatePartitionMemberWitness(1, 2, state, 7),),
    )
    comparison = DecisionDagComparisonWitness(
        5, RouteComparison(5, "jz", 7, 6, 4), state,
    )
    raw_dag = DecisionDagRouteWitness(
        state, 7, 5, 0x1500, (5,), (0x1500,), (comparison,), (), (raw_bridge,),
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.STATE_PARTITION,
        1, 2, 0x1200, 7, 6, 0x1100, 0x1600, (1, 2), ((1, 2),),
        partition_witness=group,
        decision_dag_witness=raw_dag,
    )
    route = StateWriteTransition(1, 7, 6, False, None, semantic_route_fact=fact)
    kwargs = dict(
        source=source,
        source_catalog=catalog,
        block_refs_by_serial=refs,
        canonical_evidence=evidence,
        state_identity=state,
    )
    assert producer_module.adapt_state_transition_route(route, **kwargs) is canonical_proof

    wrong_namespace = replace(
        raw_dag,
        comparisons=(replace(comparison, state_identity=register),),
    )
    extra_bridge = ExactU32XduNamespaceBridge(2, 0x1200, 0x1200, state, register, 4, 8)
    for drifted_dag in (
        wrong_namespace,
        replace(raw_dag, bridges=()),
        replace(raw_dag, bridges=(raw_bridge, extra_bridge)),
        replace(raw_dag, bridges=(replace(raw_bridge, instruction_ea=0x1501),)),
    ):
        with pytest.raises(ValueError, match="zero or multiple canonical matches"):
            producer_module.adapt_state_transition_route(
                replace(route, semantic_route_fact=replace(fact, decision_dag_witness=drifted_dag)),
                **kwargs,
            )
