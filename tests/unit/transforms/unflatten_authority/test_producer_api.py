from __future__ import annotations

import pytest
from dataclasses import replace
from types import SimpleNamespace

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
        DecisionDagRouteWitness,
        SemanticRouteFact,
        SemanticRouteFactKind,
        build_canonical_semantic_evidence,
        canonical_semantic_evidence_from_proofs,
    )
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import FlowGraph
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
        ((2, RouteComparison(2, "jz", 7, 3, 4)),), (),
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


def test_concrete_entry_route_owns_its_exact_rebound_predecessor_proof() -> None:
    """Entry-prefix authority is selected by its physical fact, not a back edge."""

    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        canonical_semantic_evidence_from_proofs,
    )
    from d810.transforms.minimal_unflatten_emit import ConcreteEntryRouteForecast
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    entry_proof = replace(
        proof,
        diagnostic_provenance=(("fact_id", "entry-prefix-fact"),),
    )
    evidence = canonical_semantic_evidence_from_proofs(
        native_key=proposal.route_evidence.native_key,
        generation=proposal.route_evidence.generation,
        proofs=(entry_proof,),
    )
    assert proof.state_write is not None
    entry = ConcreteEntryRouteForecast(
        normalized_state=7,
        target_handler=2,
        source_kinds=("native_bound",),
        physical_fact_id="entry-prefix-fact",
        canonical_proof_id=evidence.route_proofs[0].proof_id,
        source_identity=refs[0].identity,
        source_anchor_ea=0x1000,
        target_identity=refs[2].identity,
        state_identity=proof.state_write.state_variable,
        proof_owner_identity="entry-prefix:blk0@0x1000",
    )

    # The unrelated selected-backedge index is intentionally empty.  A concrete
    # entry owns the exact canonical proof named by its rebound physical fact.
    owners: dict[str, str] = {}
    resolved = producer_api.resolve_concrete_entry_route(
        entry,
        source=source,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=evidence,
        selected_transitions=producer_api.TransitionRouteSelectionIndex(()),
        proof_owners=owners,
    )
    assert resolved.proof_id == entry_proof.proof_id
    assert owners == {resolved.proof_id: "entry-prefix:blk0@0x1000"}


def test_concrete_entry_route_rejects_missing_ambiguous_drifted_or_duplicate_owners() -> None:
    """Concrete-entry proof selection has no state/target fallback or shared owner."""

    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        canonical_semantic_evidence_from_proofs,
    )
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    entry_proof = replace(
        proof,
        diagnostic_provenance=(("fact_id", "entry-prefix-fact"),),
    )
    evidence = canonical_semantic_evidence_from_proofs(
        native_key=proposal.route_evidence.native_key,
        generation=proposal.route_evidence.generation,
        proofs=(entry_proof,),
    )
    assert proof.state_write is not None
    route = ConcreteEntryRouteForecast(
        7, 2, ("native_bound",), "entry-prefix-fact",
        evidence.route_proofs[0].proof_id, refs[0].identity,
        0x1000, refs[2].identity, proof.state_write.state_variable,
        "entry-prefix:blk0@0x1000",
    )
    kwargs = dict(
        source=source,
        source_catalog=proposal.source_identity_catalog,
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
    state_write = entry_proof.state_write
    assert state_write is not None
    original_identity = state_write.identity
    object.__setattr__(state_write, "identity", refs[1].identity)
    try:
        with pytest.raises(ValueError, match="source/state"):
            producer_api.resolve_concrete_entry_route(route, proof_owners={}, **kwargs)
    finally:
        object.__setattr__(state_write, "identity", original_identity)
    with pytest.raises(ValueError, match="already owned"):
        producer_api.resolve_concrete_entry_route(
            route, proof_owners={entry_proof.proof_id: "backedge"}, **kwargs,
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
    native_proof = native_evidence.route_proofs[0]
    assert producer_api.adapt_native_bound_transition_route(
        native, **{**kwargs, "canonical_evidence": native_evidence},
    ) is native_proof
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
            comparisons=(
                (1, RouteComparison(1, "jz", 7, 2, 3)),
            ),
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

    # Legacy source-kinds text is intentionally non-authoritative.
    assert producer_api.adapt_native_bound_transition_route(
        replace(native, fact_id="foreign"), **kwargs,
    ) is proof

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


def test_bootstrap_transition_selects_actual_recovery_fact_and_entry_view() -> None:
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
        SemanticRouteFactKind,
        build_canonical_semantic_evidence,
    )
    from d810.analyses.control_flow.route_predicate import RouteComparison
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
    from d810.ir.expressions import ValueOpKind
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
    from d810.transforms.cfg_transaction import NativeBlockRef
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
            7: block(7, 0x1700, (), (6,)),
            11: block(11, 0x1B00, (), (6,)),
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
    source_catalog = producer_api.build_source_identity_catalog(
        graph, refs, native_key=key, source_generation=1,
    )
    dag_route = _DecisionDagStateRoute(
        target=7,
        certified_targets=frozenset({7}),
        entry_serial=6,
        path_serials=(6,),
        path_anchors=(0x1600,),
        comparisons=((6, RouteComparison(6, "jz", 7, 7, 11)),),
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
        tuple((serial, ref.identity) for serial, ref in refs.items()),
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
    forecast = BootstrapEntryRouteForecast(1, 7, 7, 0x1100, 0x1700)
    assert producer_api.resolve_bootstrap_entry_route(
        forecast,
        source=graph,
        source_catalog=source_catalog,
        block_refs_by_serial=refs,
        selected_transitions=selected,
    ) is proof

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
        ("target_identity", refs[11].identity),
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
    for field, value in (("target_identity", refs[11].identity), ("target_anchor_ea", 0xDEAD)):
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
