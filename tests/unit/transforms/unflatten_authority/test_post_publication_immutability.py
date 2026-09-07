"""Phase 3 (d81-h8va): published authority values are genuinely immutable.

The invariant this module proves is *dynamic*, not stylistic: for the record
types that used to rewrite their own fields, constructing one performs **zero**
writes from inside ``__post_init__``.

Publication definition (the same one the census harness implements): a record is
published at the earliest of (P1) its own ``__post_init__`` returning to the
caller, (P2) its content identity being materialised while construction is still
running, or (P3) it being registered into a session arena / registry / proof
table / inventory while still inside construction.  Driving the number of
``__post_init__`` writes to zero makes the exact placement of P2 and P3 inside
construction irrelevant: between the generated ``__init__`` and the return of
``__post_init__`` there is no write left to be on the wrong side of them.

The counter here is the same mechanism the record itself is frozen with.  Every
one of these classes is ``frozen=True, slots=True``, so the only route to a
field's ``__set__`` is ``object.__setattr__``; replacing the slot's
``member_descriptor`` with a counting one therefore observes *every* write.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager

import pytest

from d810.transforms.unflatten_authority.ids import _claim_factory, _subject_factory

from .helpers import authority_id, import_authority_model
from .test_evaluate import _retirement_catalog, _role_subject
from .test_model import _subject, _valid_proposal

model = import_authority_model()


class _CountingSlot:
    """A slot descriptor that records the writing frame's function name."""

    __slots__ = ("orig", "name", "log")

    def __init__(self, orig, name, log):
        self.orig = orig
        self.name = name
        self.log = log

    def __get__(self, inst, owner=None):
        if inst is None:
            return self
        return self.orig.__get__(inst, owner)

    def __set__(self, inst, value):
        self.log.append((type(inst).__name__, self.name, sys._getframe(1).f_code.co_name))
        self.orig.__set__(inst, value)

    def __delete__(self, inst):
        self.orig.__delete__(inst)


@contextmanager
def _write_log(*classes: type):
    """Record every ``object.__setattr__`` reaching a field of ``classes``."""

    log: list[tuple[str, str, str]] = []
    restore: list[tuple[type, str, object]] = []
    for cls in classes:
        names = getattr(cls, "__slots__", ())
        if isinstance(names, str):
            names = (names,)
        for name in names:
            orig = cls.__dict__.get(name)
            if type(orig).__name__ != "member_descriptor":
                continue
            restore.append((cls, name, orig))
            setattr(cls, name, _CountingSlot(orig, name, log))
    try:
        yield log
    finally:
        for cls, name, orig in reversed(restore):
            setattr(cls, name, orig)


def _post_init_writes(log) -> list[tuple[str, str, str]]:
    return [row for row in log if row[2] == "__post_init__"]


def _local_alias_claim(*, host_ea: int = 0x1000):
    owner = _subject(
        model, model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.EFFECT_SITE,
        model.BlockSubjectLocator(_role_subject(
            model.SemanticSubjectRole.EFFECT_SITE, "local-alias",
        ).block_ref, host_ea),
    )
    return _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=owner,
        step_index=0,
        host_ea=host_ea,
        host_opcode=1,
        alias_token="alias",
        base_token="base",
        host_text_sha1=None,
        value_size=4,
        step_digest=authority_id("local-alias-step"),
        source_generation=3,
    )


def _retirement_claim(*, member_order: str = "canonical"):
    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")

    corridor = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=member0.block_ref,
        anchor_ea=member0.anchor_ea,
        locator=model.CorridorSubjectLocator(
            authority_id("phase3-retirement-corridor"),
            member0.block_ref, member0.anchor_ea,
            (member0.block_ref, member1.block_ref),
            (member0.anchor_ea, member1.anchor_ea),
        ),
    )
    catalog = _retirement_catalog(
        model,
        (member0.block_ref, member1.block_ref),
        (member0.anchor_ea, member1.anchor_ea),
        3,
    )
    members = model.canonical_model_order((member0, member1), "member_subjects")
    if member_order == "reversed":
        members = tuple(reversed(members))
    return _claim_factory(
        model.RetiredDispatcherInfrastructureClaim,
        kind=model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        infrastructure_subject=member0,
        corridor_subject=corridor,
        member_subjects=members,
        candidate_evidence_ids=tuple(sorted({
            evidence_id
            for item in catalog.candidates
            for evidence_id in item.evidence_ids
        })),
        source_generation=3,
        candidate_catalog=catalog,
    )


def test_route_claim_construction_performs_no_post_init_writes() -> None:
    """``EquivalentSemanticRouteClaim`` normalises before the record exists."""

    with _write_log(model.EquivalentSemanticRouteClaim) as log:
        _valid_proposal(model)
    assert _post_init_writes(log) == []


def test_proposal_construction_performs_no_post_init_writes() -> None:
    """``ProposedUnflattenContract`` only validates once it exists."""

    values = _valid_proposal(model)
    with _write_log(model.ProposedUnflattenContract) as log:
        model.ProposedUnflattenContract(**values)
    assert _post_init_writes(log) == []


def test_revalidating_a_published_proposal_mutates_nothing() -> None:
    """Re-entering ``__post_init__`` on a published proposal writes nothing.

    This is the exact shape the census caught: ``SourceBoundRouteAuthority``
    revalidates its proposal by calling ``proposal.__post_init__()`` again, and
    every normalisation write in that method landed on a record whose content
    ID had already been minted.
    """

    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    with _write_log(model.ProposedUnflattenContract) as log:
        proposal.__post_init__()
    assert log == []


def test_local_alias_claim_construction_performs_no_post_init_writes() -> None:
    """``LocalAliasEffectScalarizationClaim`` validates ``host_ea`` in place."""

    with _write_log(model.LocalAliasEffectScalarizationClaim) as log:
        _local_alias_claim()
    assert _post_init_writes(log) == []


def test_retirement_claim_construction_performs_no_post_init_writes() -> None:
    """``RetiredDispatcherInfrastructureClaim`` takes canonical members."""

    with _write_log(model.RetiredDispatcherInfrastructureClaim) as log:
        _retirement_claim()
    assert _post_init_writes(log) == []


def test_retirement_claim_refuses_non_canonical_member_order() -> None:
    """Coercion is replaced by rejection: the caller must pass canonical order."""

    with pytest.raises(ValueError, match="canonical order"):
        _retirement_claim(member_order="reversed")


def test_proposal_refuses_a_claim_sequence_it_would_have_coerced() -> None:
    """A proposal no longer coerces its claims field; it refuses a non-tuple."""

    values = _valid_proposal(model)
    values["claims"] = list(values["claims"])
    with pytest.raises(TypeError, match="exact tuple"):
        model.ProposedUnflattenContract(**values)


def test_canonical_model_order_is_the_order_the_records_demand() -> None:
    """The producer-side helper and the record-side check agree by construction."""

    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    ordered = model.canonical_model_order((member1, member0), "member_subjects")
    assert ordered == model.canonical_model_order(ordered, "member_subjects")
    assert set(ordered) == {member0, member1}


def test_entry_liveness_revalidation_does_not_write_published_descendants(monkeypatch):
    """Exercise real proposal/binding/admission reentry, including nested records."""
    from .test_transaction_api import (
        test_binds_no_provider_entry_endpoint_liveness_to_its_exact_redirect_fact,
        test_closed_entry_forecast_flows_from_canonical_proof_to_transaction_binding,
    )

    published = {}  # Retain the objects: id reuse cannot invent publication.
    writes = []
    reentered = set()

    class PublishedSlot(_CountingSlot):
        def __set__(self, inst, value):
            if id(inst) in published:
                self.log.append((type(inst).__name__, self.name))
            self.orig.__set__(inst, value)

    classes = (
        model.EntryEndpointLivenessForecast,
        model.EntryEndpointLivenessAllowance,
        model.BoundEntryEndpointLivenessAllowance,
        model.PatchStepEvidencePayload,
    )
    for cls in classes:
        for name in cls.__slots__:
            original_slot = cls.__dict__.get(name)
            if type(original_slot).__name__ == "member_descriptor":
                monkeypatch.setattr(cls, name, PublishedSlot(original_slot, name, writes))
        original_post_init = cls.__post_init__

        def post_init(self, original=original_post_init):
            if id(self) in published:
                reentered.add(type(self))
            original(self)
            published[id(self)] = self

        monkeypatch.setattr(cls, "__post_init__", post_init)

    test_binds_no_provider_entry_endpoint_liveness_to_its_exact_redirect_fact()
    test_closed_entry_forecast_flows_from_canonical_proof_to_transaction_binding()
    assert set(classes) <= reentered
    assert writes == []
