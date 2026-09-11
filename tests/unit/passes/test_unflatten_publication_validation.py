"""Publication must reject malformed authority without a persistence roundtrip."""

import pytest

from d810.passes.unflatten.state_machine import _typed_or_empty_unflatten_plan
from d810.transforms.unflatten_authority import ids
from d810.transforms.unflatten_authority.proposal import (
    ProposalAccepted,
    ProposalRejected,
    validate_proposal,
)
from d810.transforms.unflatten_authority.transaction_facts import (
    TransactionFacts,
    fact_scope,
)
from tests.unit.passes.test_pipeline_threading import _typed_pipeline_plan
from tests.unit.transforms.unflatten_authority.test_proposal import (
    _proposal_and_plan_ids,
    _typed_plan,
)


@pytest.mark.parametrize("mode", [None, "1"])
def test_valid_publication_does_not_serialize_and_parse_proposal(mode, monkeypatch):
    if mode is None:
        monkeypatch.delenv("D810_PRODUCER_STRUCTURAL_VALIDATION", raising=False)
    else:
        monkeypatch.setenv("D810_PRODUCER_STRUCTURAL_VALIDATION", mode)
    # Restoring the persistence roundtrip must break this work-elimination test.
    # Route-only fixture isolates publication from the separate exact-effect
    # correlation check, whose persistence check is intentionally unchanged.
    plan, _ = _typed_plan(_proposal_and_plan_ids()[0])
    original = ids.canonical_decode
    decodes = []

    def counted(encoded):
        decodes.append(len(encoded))
        return original(encoded)

    monkeypatch.setattr(ids, "canonical_decode", counted)
    assert _typed_or_empty_unflatten_plan(plan) is plan
    assert decodes == []


@pytest.mark.parametrize("damage", ["claim_id", "group_id", "block_order"])
@pytest.mark.parametrize("mode", [None, "1"])
def test_publication_keeps_descendant_rejection_before_returning_edits(damage, mode, monkeypatch):
    if mode is None:
        monkeypatch.delenv("D810_PRODUCER_STRUCTURAL_VALIDATION", raising=False)
    else:
        monkeypatch.setenv("D810_PRODUCER_STRUCTURAL_VALIDATION", mode)
    # A live field walker or top-level post-init alone must not admit these.
    plan = _typed_pipeline_plan()
    proposal = plan.unflatten_proposal
    if damage == "claim_id":
        object.__setattr__(proposal.claims[0], "claim_id", "sha256:" + "f" * 64)
    elif damage == "group_id":
        object.__setattr__(proposal.route_evidence, "atomic_group_id", "sha256:" + "f" * 64)
    else:
        catalog = proposal.source_identity_catalog
        object.__setattr__(catalog, "blocks", tuple(reversed(catalog.blocks)))

    strict = validate_proposal(plan, proposal)
    assert isinstance(strict, ProposalRejected)
    published = _typed_or_empty_unflatten_plan(plan)
    assert published.steps == ()
    assert published.new_blocks == ()
    assert published.metadata_dict()["unflatten_producer_abstention"] == strict


@pytest.mark.parametrize("mode", ["0", "unexpected"])
def test_publication_strict_rollback_still_roundtrips(mode, monkeypatch):
    monkeypatch.setenv("D810_PRODUCER_STRUCTURAL_VALIDATION", mode)
    plan, _ = _typed_plan(_proposal_and_plan_ids()[0])
    original = ids.canonical_decode
    decodes = []

    def counted(encoded):
        decodes.append(len(encoded))
        return original(encoded)

    monkeypatch.setattr(ids, "canonical_decode", counted)
    assert _typed_or_empty_unflatten_plan(plan) is plan
    assert decodes


@pytest.mark.parametrize("mode", [None, "1"])
def test_publication_switch_does_not_weaken_public_transaction_validation(mode, monkeypatch):
    if mode is None:
        monkeypatch.delenv("D810_PRODUCER_STRUCTURAL_VALIDATION", raising=False)
    else:
        monkeypatch.setenv("D810_PRODUCER_STRUCTURAL_VALIDATION", mode)
    plan, proposal = _typed_plan(_proposal_and_plan_ids()[0])
    original = ids.canonical_decode
    decodes = []

    def counted(encoded):
        decodes.append(len(encoded))
        return original(encoded)

    monkeypatch.setattr(ids, "canonical_decode", counted)
    assert isinstance(validate_proposal(plan, proposal), ProposalAccepted)
    assert decodes


def test_exact_effect_publication_keeps_its_separate_strict_correlation(monkeypatch):
    plan = _typed_pipeline_plan()
    monkeypatch.setenv("D810_PRODUCER_STRUCTURAL_VALIDATION", "0")
    strict = _typed_or_empty_unflatten_plan(plan)
    assert strict is plan
    original = ids.canonical_decode
    decodes = []

    def counted(encoded):
        decodes.append(len(encoded))
        return original(encoded)

    monkeypatch.setattr(ids, "canonical_decode", counted)
    monkeypatch.setenv("D810_PRODUCER_STRUCTURAL_VALIDATION", "1")
    assert _typed_or_empty_unflatten_plan(plan) is strict
    assert decodes


@pytest.mark.parametrize("target", ["claim", "subject"])
def test_structural_reconstruction_rejects_forged_lazy_descendant_ids(target):
    proposal = _proposal_and_plan_ids()[0]
    claim = proposal.claims[0]
    record, field = ((claim, "claim_id") if target == "claim"
                     else (claim.source_subject, "subject_id"))
    object.__setattr__(record, field, "sha256:" + "f" * 64)
    with pytest.raises(ValueError):
        ids.validate_producer_proposal_structure(proposal)


def test_structural_reconstruction_does_not_inherit_owned_validation_bypass():
    owner = TransactionFacts()
    try:
        with fact_scope(owner):
            proposal = owner.capture(_proposal_and_plan_ids()[0])
            assert owner.contains(proposal)
            object.__setattr__(proposal.claims[0], "claim_id", "sha256:" + "f" * 64)
            with pytest.raises(ValueError):
                ids.validate_producer_proposal_structure(proposal)
    finally:
        owner.close()
