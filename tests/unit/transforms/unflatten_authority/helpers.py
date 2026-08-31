"""Small test-only helpers shared by the authority migration checkpoints."""

from __future__ import annotations

import importlib
import hashlib
from dataclasses import dataclass

from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority.ids import _subject_factory


@dataclass(frozen=True, slots=True)
class ProjectedSiteFixture:
    """Real producer/inventory objects used by semantic-site tests."""
    source_authority: object
    plan: object
    attempt_id: object
    source_inventory: object
    projected_inventory: object
    claims: tuple[object, ...]
    patch_step_facts: tuple[object, ...]
    raw_fact: object
    legacy_effective: object


def projected_site_fixture() -> ProjectedSiteFixture:
    """Build a projected-site fixture through the real producer/binder path."""
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts

    # Import lazily: the compiler fixture itself imports this helper module.
    from .test_bind import _compiler_redirect_goto_case

    (
        source_authority,
        plan,
        source_inventory,
        projected_inventory,
        patch_step_facts,
        attempt_id,
        *_ignored,
    ) = _compiler_redirect_goto_case()
    owners = frozenset(row.owner_serial for row in source_inventory.effects)
    raw_fact = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
        raw_gate_facts=GenericEffectfulGateFacts(
            True, owners, owners, frozenset(), "projected-site-fixture",
        ),
    )
    return ProjectedSiteFixture(
        source_authority=source_authority,
        plan=plan,
        attempt_id=attempt_id,
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
        claims=plan.unflatten_proposal.claims,
        patch_step_facts=patch_step_facts,
        raw_fact=raw_fact,
        legacy_effective=None,
    )


def realize_projected_routes_for_test(**values):
    """Migrate inherited callers through one complete, canonical envelope.

    Older tests intentionally supplied only the structural six-tuple.  The
    public C closure now receives the complete transaction-bound envelope;
    this helper derives the missing registered raw fact, effective DTO shadow,
    and recomputed projected authority ID from those exact fixture objects.
    Explicit values are never replaced, which keeps adversarial tests honest.
    """
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from d810.transforms.unflatten_authority.ids import patch_step_fact_id, projected_authority_id
    from d810.transforms.unflatten_authority.model import RawEffectGatePhaseFact

    source_authority = values["source_authority"]
    plan = values["plan"]
    source_inventory = values["source_inventory"]
    projected_inventory = values["projected_inventory"]
    patch_step_facts = values.get("patch_step_facts", ())
    if type(patch_step_facts) is tuple:
        patch_step_facts = tuple(sorted(patch_step_facts, key=patch_step_fact_id))
    attempt_id = values["attempt_id"]
    claims = values.get("claims", plan.unflatten_proposal.claims)
    inferred_raw_gate_facts = None
    if "raw_effect_gate_fact" not in values:
        # The raw transport DTO remains in the source-owner serial namespace.
        # A projected corridor may retire an effect owner, so only its
        # retained partition is inferred through stable source-ref
        # correspondence.
        owners = frozenset(
            row.owner_serial
            for row in source_inventory.effects
            if row.owner_serial in source_inventory.reachable_serials
        )
        source_refs = {
            row.serial: row.block_ref
            for row in source_inventory.blocks
        }
        projected_serial_by_ref = projected_inventory.serial_by_ref
        retained = frozenset(
            serial for serial in owners
            if (
                (ref := source_refs.get(serial)) is not None
                and (projected_serial := projected_serial_by_ref.get(ref)) is not None
                and projected_serial in projected_inventory.reachable_serials
            )
        )
        inferred_raw_gate_facts = GenericEffectfulGateFacts(
            not (owners - retained), owners, retained, owners - retained,
            "inherited-helper",
        )
        try:
            raw_fact = bind.bind_raw_effect_gate_phase_fact(
                source_inventory=source_inventory,
                projected_inventory=projected_inventory,
                raw_gate_facts=inferred_raw_gate_facts,
            )
        except (TypeError, ValueError):
            # A malformed source/projected pair has no canonical raw fact to
            # derive.  Leave that input absent and let the public transaction
            # boundary return its typed rejection; do not mint a substitute.
            raw_fact = None
        values["raw_effect_gate_fact"] = raw_fact
    else:
        raw_fact = values["raw_effect_gate_fact"]
    if "authority_id" not in values:
        try:
            values["authority_id"] = projected_authority_id(
                attempt_id=attempt_id,
                proposal_id=source_authority.proposal_id,
                source_authority_id=source_authority.source_authority_id,
                plan_id=plan.plan_id,
                claims=claims,
                patch_step_facts=patch_step_facts,
                source_inventory=source_inventory,
                projected_inventory=projected_inventory,
                raw_effect_gate_fact=raw_fact,
            )
        except (TypeError, ValueError):
            # As above, adversarial envelopes must be rejected by the public
            # transaction-owned boundary rather than reconstructed here.
            values["authority_id"] = None
    if "legacy_effective_gate_facts" not in values:
        # Match transaction_api's optimistic legacy comparison exactly: it is
        # a source-namespace compatibility shadow.  A raw producer DTO and a
        # bound phase fact intentionally have disjoint representations: the
        # former retains source serials, while the latter retains stable
        # owner coordinates.  Never read DTO fields from the bound fact.
        if inferred_raw_gate_facts is not None:
            legacy_source_serials = (
                inferred_raw_gate_facts.pre_effectful_block_serials
            )
            legacy_reason = inferred_raw_gate_facts.reason
        elif type(raw_fact) is RawEffectGatePhaseFact:
            legacy_source_serials = frozenset(
                source_inventory.serial_by_ref[owner.ref]
                for owner in raw_fact.pre_effectful_source_owners
            )
            legacy_reason = "bound-raw-effect-gate-compatibility"
        else:
            # Keep malformed explicit envelopes at the public transaction
            # boundary.  This helper must not forge producer transport data.
            legacy_source_serials = frozenset()
            legacy_reason = "bound-raw-effect-gate-compatibility"
        values["legacy_effective_gate_facts"] = GenericEffectfulGateFacts(
            True,
            legacy_source_serials,
            legacy_source_serials,
            frozenset(),
            legacy_reason,
        )
    values["claims"] = claims
    values["patch_step_facts"] = patch_step_facts
    values["raw_effect_gate_fact"] = raw_fact
    return bind.realize_projected_routes(**values)


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


def exact_fixture(
    *, optional_owner: bool = False,
    discarded_effect_kind: str = "call",
    shared_terminal: bool = False,
    producer_inputs_only: bool = False,
):
    """Build the shared canonical producer fixture for backend tests."""

    from d810.analyses.control_flow.effect_branch_exclusion import build_exact_state_branch_effect_exclusion
    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticCarrierProof, SemanticCorridorPoint,
        canonical_semantic_evidence_from_proofs,
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
    from d810.transforms.unflatten_authority import model, producer_api
    from d810.transforms.unflatten_authority.model import UseDefFragmentWitness

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    state = StorageIdentity(StorageIdentityKind.STACK, 4)
    state_number = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7)
    state_stack = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
    if discarded_effect_kind == "call":
        discarded_effect = InsnSnapshot(
            0, 0x4000, (), l=state_number, kind=InsnKind.CALL,
            is_call=True, raw_opcode=0,
        )
    elif discarded_effect_kind == "store":
        discarded_effect = InsnSnapshot(
            0, 0x4000, (), l=state_number, d=state_stack,
            kind=InsnKind.STORE, value_op_kind=ValueOpKind.STORE,
            display_text="discarded = state", raw_opcode=0,
        )
    elif discarded_effect_kind == "call_store":
        discarded_effect = (
            InsnSnapshot(
                0, 0x4000, (), l=state_number, kind=InsnKind.CALL,
                is_call=True, raw_opcode=0,
            ),
            InsnSnapshot(
                0, 0x4001, (), l=state_number, d=state_stack,
                kind=InsnKind.STORE, value_op_kind=ValueOpKind.STORE,
                display_text="discarded = state", raw_opcode=0,
            ),
        )
    else:
        raise ValueError("discarded_effect_kind must be call, store, or call_store")
    selected_instructions = (
        InsnSnapshot(0, 0x3000, (), kind=InsnKind.NOP, raw_opcode=0),
        InsnSnapshot(
            0, 0x3001, (),
            l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
            kind=InsnKind.GOTO, raw_opcode=0,
        ),
    ) if shared_terminal else (
        InsnSnapshot(0, 0x3000, (), kind=InsnKind.NOP, raw_opcode=0),
    )
    discarded_effects = (
        discarded_effect
        if type(discarded_effect) is tuple
        else (discarded_effect,)
    )
    discarded_goto_ea = 0x4000 + len(discarded_effects)
    discarded_instructions = (
        *discarded_effects,
        InsnSnapshot(
            0, discarded_goto_ea, (),
            l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
            kind=InsnKind.GOTO, raw_opcode=0,
        ),
    ) if shared_terminal else discarded_effects
    specs = (
        (0, (1,), (), 0x1000, (InsnSnapshot(0, 0x1000, (), l=state_number, d=state_stack, kind=InsnKind.MOV, value_op_kind=ValueOpKind.MOVE, raw_opcode=0), InsnSnapshot(0, 0x1001, (), l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=1), kind=InsnKind.GOTO, raw_opcode=0))),
        (1, (3, 2), (0,), 0x2000, (InsnSnapshot(0, 0x2000, (), kind=InsnKind.NOP, value_op_kind=ValueOpKind.VENDOR, raw_opcode=0), InsnSnapshot(0, 0x2001, (), l=state_stack, r=state_number, d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2), kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ, is_conditional_jump=True, raw_opcode=0),)),
        (2, (4,) if shared_terminal else (), (1,), 0x3000, selected_instructions),
        (3, (4,) if shared_terminal else (), (1,), 0x4000, discarded_instructions),
        (4, (), (2, 3) if shared_terminal else (), 0x5000, (InsnSnapshot(0, 0x5000, (), kind=InsnKind.NOP, raw_opcode=0),)),
    )
    source = FlowGraph({serial: BlockSnapshot(serial, 0, succs, preds, 0, ea, insns,
        tail_opcode=insns[-1].opcode if insns else None,
        kind=BlockKind.TWO_WAY if len(succs) == 2 else BlockKind.ONE_WAY if succs else BlockKind.ZERO_WAY,
        tail_kind=insns[-1].kind if insns else None,
        raw_tail_opcode=insns[-1].raw_opcode if insns else None)
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
    evidence = canonical_semantic_evidence_from_proofs(
        native_key=key,
        generation=1,
        proofs=(route,),
    )
    witness = UseDefFragmentWitness(authority_id("fragment"), state, (refs[0],), authority_id("redirect"), True, True, 0, ())
    if producer_inputs_only:
        return source, evidence, witness, refs
    if discarded_effect_kind != "call_store":
        exclusion = build_exact_state_branch_effect_exclusion(
            source, source, normalized_state=7, source_serial=0,
            predicate_serial=1, selected_target_serial=2,
            discarded_effect_serial=3, state_identity=state,
        )
        assert exclusion is not None
        proposal = producer_api.build_proposal(plan_id=authority_id("plan"), source=source, block_refs_by_serial=refs, source_generation=1, canonical_route_evidence=evidence, selected_route_proof_ids=(evidence.route_proofs[0].proof_id,), exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,), state_identity=state, use_def_witness=witness)
        return source, proposal, exclusion, refs

    exclusions = tuple(
        build_exact_state_branch_effect_exclusion(
            source, source, normalized_state=7, source_serial=0,
            predicate_serial=1, selected_target_serial=2,
            discarded_effect_serial=3, state_identity=state,
            discarded_effect_ea=effect_ea,
        )
        for effect_ea in (0x4000, 0x4001)
    )
    assert all(exclusion is not None for exclusion in exclusions)
    proposal = producer_api.build_proposal(
        plan_id=authority_id("plan"), source=source,
        block_refs_by_serial=refs, source_generation=1,
        canonical_route_evidence=evidence,
        selected_route_proof_ids=(evidence.route_proofs[0].proof_id,),
        exact_state_effect_exclusions=exclusions,
        dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,), state_identity=state,
        use_def_witness=witness,
    )
    return source, proposal, exclusions, refs


def observed_patch_binding_for_test(authority, *, helper_serials=None):
    """Mint the exact neutral observed binding used by authority unit tests."""
    from d810.transforms.cfg_transaction import PlanBlockRef
    from d810.transforms.patch_binding import observed_patch_binding
    from d810.transforms.unflatten_authority import model

    if type(authority) is not model.BoundUnflattenAuthority:
        raise TypeError("test observed binding requires BoundUnflattenAuthority")
    rows = tuple(
        (ref, serial if helper_serials is None else helper_serials[ref])
        for ref, serial in authority.patch_binding.bindings
        if type(ref) is PlanBlockRef
    )
    return observed_patch_binding(authority.patch_binding, rows)
