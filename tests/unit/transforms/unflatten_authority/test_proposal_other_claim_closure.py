"""Remaining producer claims retain their constructor and identity checks."""
import pytest
from d810.core.structural_identity import StructuralTable
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import authority_id, canonical_bytes, validate_canonical_roundtrip
from .test_model import _subject, _retirement_catalog, block_ref, state_identity
from .test_bind import _detached_subject
from .test_proposal_terminal_claim_closure import _terminal_claim


def _retirement():
    base = _terminal_claim()
    refs = base.cycle_subject.locator.member_refs
    anchors = base.cycle_subject.locator.member_anchor_eas
    catalog = _retirement_catalog(model, refs, anchors, 0)
    members = tuple(_subject(model, model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        model.BlockSubjectLocator(ref, ea)) for ref, ea in zip(refs, anchors))
    ids = tuple(sorted({item for candidate in catalog.candidates for item in candidate.evidence_ids}))
    return model.RetiredDispatcherInfrastructureClaim(
        model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        members[0], base.cycle_subject, members, ids, 0, catalog)


def _detached():
    role = model.SemanticSubjectRole
    return model.DetachedDeadHandlerComponentClaim(
        model.UnflattenClaimKind.DETACHED_DEAD_HANDLER_COMPONENT,
        _detached_subject(role.DISPATCHER_ENTRY, 1),
        (_detached_subject(role.AUTHORITATIVE_HANDLER, 2),),
        (_detached_subject(role.AUTHORITATIVE_HANDLER, 4),),
        (_detached_subject(role.DETACHED_DEAD_HANDLER_COMPONENT, 2),),
        (_detached_subject(role.DISPATCHER_INFRASTRUCTURE, 1),), 3)


def _effect():
    b0, b1 = block_ref("b0"), block_ref("b1")
    role = model.SemanticSubjectRole
    def block(ref, ea, purpose):
        return _subject(model, model.SemanticSubjectKind.BLOCK, purpose,
                        model.BlockSubjectLocator(ref, ea))
    effect = _subject(model, model.SemanticSubjectKind.EFFECT, role.EFFECT_SITE,
                     model.EffectSubjectLocator(b0, 0x1000, 0x1008, model.EffectSiteKind.STORE))
    return model.ExactInfeasibleEffectClaim(
        model.UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT, effect,
        block(b0, 0x1000, role.EXACT_EFFECT_SOURCE),
        block(b0, 0x1000, role.EXACT_EFFECT_PREDICATE),
        block(b1, 0x1100, role.EXACT_EFFECT_SELECTED_TARGET),
        effect, 1, state_identity(), 4, 0x1004, 0x1008, 0x1008,
        model.SemanticEdgeRole.DIRECT, (authority_id("exact-proof"),),
        model.ProviderConsensusWitness(model.ProviderConsensusMode.NOT_APPLICABLE, ()), 0)


@pytest.mark.parametrize("factory", (_retirement, _detached, _effect))
def test_producer_claim_constructor_projection_preserves_canonical_bytes(factory):
    value = factory()
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_producer_claim(table, value)
    object.__setattr__(value, "source_generation", 77)
    restored = proposal_inputs.materialize_producer_claim(table, ref)
    assert canonical_bytes(restored) == expected


@pytest.mark.parametrize("factory", (_retirement, _detached, _effect))
def test_producer_claim_reconstruction_rejects_tampered_supplied_id(factory):
    value = factory()
    object.__setattr__(value, "claim_id", "sha256:" + "f" * 64)
    with pytest.raises(ValueError):
        validate_canonical_roundtrip(value, type(value))
    table = StructuralTable()
    ref = proposal_inputs.capture_producer_claim(table, value)
    with pytest.raises(ValueError):
        proposal_inputs.materialize_producer_claim(table, ref)
