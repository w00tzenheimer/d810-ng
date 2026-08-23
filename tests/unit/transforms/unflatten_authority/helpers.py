"""Small test-only helpers shared by the authority migration checkpoints."""

from __future__ import annotations

import importlib
import hashlib

from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority.ids import _subject_factory


def import_authority_model():
    """Import the future model at the package boundary under test."""

    return importlib.import_module("d810.transforms.unflatten_authority.model")


def authority_id(seed: str = "a") -> str:
    """Return a structurally valid supplied authority ID."""

    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def block_ref(token: str = "b", version: int = 1) -> LogicalBlockRef:
    return LogicalBlockRef("authority-test", token, version)


def state_identity() -> StorageIdentity:
    return StorageIdentity(StorageIdentityKind.STACK, 0x40)


def edge_role() -> SemanticEdgeRole:
    return SemanticEdgeRole.DIRECT


def subject_kwargs(model, *, kind, role, locator, subject_id=None):
    """Build the common subject fields without hiding model validation."""

    owner = getattr(locator, "block_ref", None)
    if owner is None:
        owner = getattr(locator, "source_ref", None)
    anchor = getattr(locator, "anchor_ea", None)
    if anchor is None:
        anchor = getattr(locator, "source_anchor_ea", None)
    return dict(
        kind=kind,
        role=role,
        subject_id=subject_id or authority_id("s"),
        block_ref=owner,
        anchor_ea=anchor,
        locator=locator,
    )


def block_subject(model, *, role, token="subject", anchor_ea=0x1000):
    """Build a canonical block-backed subject for evaluator fixtures."""

    ref = block_ref(token)
    locator = model.BlockSubjectLocator(ref, anchor_ea)
    return _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=role,
        block_ref=ref,
        anchor_ea=anchor_ea,
        locator=locator,
    )


def exact_fixture(*, optional_owner: bool = False):
    """Build the shared canonical producer fixture for backend tests."""

    from d810.analyses.control_flow.effect_branch_exclusion import build_exact_state_branch_effect_exclusion
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidence, SemanticCarrierProof, SemanticCorridorPoint,
        SemanticPredicateKind, SemanticPredicateProof, SemanticRouteDestination,
        SemanticRouteProof, SemanticRouteProofKind, SemanticRouteShape,
        SemanticStateWriteDeliveryKind, SemanticStateWriteProof,
    )
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import StableBlockIdentity
    from d810.ir.flowgraph import (
        BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot,
        MopSnapshot, OperandKind, PredicateKind,
    )
    from d810.ir.expressions import ValueOpKind
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api
    from d810.transforms.unflatten_authority.model import UseDefFragmentWitness

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    state = StorageIdentity(StorageIdentityKind.STACK, 4)
    state_number = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7)
    state_stack = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
    specs = (
        (0, (1,), (), 0x1000, (InsnSnapshot(0, 0x1000, (), l=state_number, d=state_stack, kind=InsnKind.MOV, value_op_kind=ValueOpKind.MOVE), InsnSnapshot(0, 0x1001, (), l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=1), kind=InsnKind.GOTO))),
        (1, (2, 3), (0,), 0x2000, (InsnSnapshot(0, 0x2000, (), kind=InsnKind.NOP, value_op_kind=ValueOpKind.VENDOR), InsnSnapshot(0, 0x2001, (), l=state_stack, r=state_number, d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2), kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ, is_conditional_jump=True),)),
        (2, (), (1,), 0x3000, (InsnSnapshot(0, 0x3000, (), kind=InsnKind.NOP),)),
        (3, (), (1,), 0x4000, (InsnSnapshot(0, 0x4000, (), l=state_number, kind=InsnKind.CALL, is_call=True),)),
        (4, (), (), 0x5000, (InsnSnapshot(0, 0x5000, (), kind=InsnKind.NOP),)),
    )
    source = FlowGraph({serial: BlockSnapshot(serial, 0, succs, preds, 0, ea, insns,
        kind=BlockKind.TWO_WAY if len(succs) == 2 else BlockKind.ONE_WAY if succs else BlockKind.ZERO_WAY)
        for serial, succs, preds, ea, insns in specs}, 0, 0x5000)
    refs = {serial: NativeBlockRef(StableBlockIdentity.from_instruction_eas(
        [ins.ea for ins in insns], native_key=key)) for serial, _s, _p, _ea, insns in specs}
    producer_api.build_source_identity_catalog(source, refs, native_key=key, source_generation=1)
    source_point = SemanticCorridorPoint(refs[0].identity, 0x1000)
    predicate_point = SemanticCorridorPoint(refs[1].identity, 0x2001)
    predicate_consumer = predicate_point
    state_write = SemanticStateWriteProof(refs[0].identity, 0x1000, state, 4, 7, (0x1000, 0x2000), None, (), SemanticStateWriteDeliveryKind.CONDITIONAL)
    predicate = SemanticPredicateProof(SemanticPredicateKind.STORAGE_EQUALS, predicate_point, predicate_consumer, (predicate_point,), state, 4, 7, None, ())
    carrier = SemanticCarrierProof(authority_id("carrier"), source_point, (predicate_point,), (source_point, predicate_point), state, 4, (7, 8), (0x1000,))
    route = SemanticRouteProof(authority_id("route"), authority_id("group"), SemanticRouteProofKind.STATE_CHOICE, SemanticRouteShape.CONDITIONAL, refs[1].identity, 0x2000, (
        SemanticRouteDestination(SemanticEdgeRole.CONDITIONAL_TAKEN, 7, refs[2].identity, 0x3000),
        SemanticRouteDestination(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, 8, refs[3].identity, 0x4000),), source_owner_identity=None if optional_owner else refs[0].identity, source_owner_anchor_ea=None if optional_owner else 0x1000, state_write=state_write, predicate=predicate, carriers=(carrier,), diagnostic_provenance=(("provider_proof_kind", "state_choice"),))
    evidence = CanonicalSemanticEvidence(key, 1, authority_id("group"), (route,))
    exclusion = build_exact_state_branch_effect_exclusion(
        source, source, normalized_state=7, source_serial=0,
        predicate_serial=1, selected_target_serial=2,
        discarded_effect_serial=3, state_identity=state,
    )
    assert exclusion is not None
    witness = UseDefFragmentWitness(authority_id("fragment"), state, (refs[0],), authority_id("redirect"), True, True, 0, ())
    proposal = producer_api.build_proposal(plan_id=authority_id("plan"), source=source, block_refs_by_serial=refs, source_generation=1, canonical_route_evidence=evidence, exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,), state_identity=state, use_def_witness=witness)
    return source, proposal, exclusion, refs
