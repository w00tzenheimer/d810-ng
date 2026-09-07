"""Differential tests for the lazy content-identity mechanism (d81-cxzv).

The oracle is the *eager* algorithm the records used before Phase 2: encode
every field except the identity field and hash the canonical bytes.  It is
re-implemented here, verbatim against ``ids._record_content_id``'s wire form,
so the test does not merely compare the implementation to itself.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from d810.transforms.unflatten_authority import ids


# --------------------------------------------------------------- oracle ---
def eager_content_id(schema: str, record: object, omitted_field: str) -> str:
    """Recompute a record content ID the way the eager code path did.

    Deliberately independent of ``ids._record_content_id``: it rebuilds the
    wire dict here rather than calling the production encoder, so a change in
    the encoder cannot silently move both sides of the comparison.
    """

    ids._ensure_registries()
    names = ids._RECORD_FIELDS[type(record)]
    wire = {
        "t": "record",
        "n": type(record).__name__,
        "v": [
            [name, ids._wire(getattr(record, name))]
            for name in names
            if name != omitted_field
        ],
    }
    preimage = (
        ids._PREFIX + schema.encode("ascii") + b"\0" + ids._json_bytes(wire)
    )
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


# ------------------------------------------------------------ machinery ---
def _build_lazy_pair():
    """Return ``(cls, derive)`` for a minimal lazily-identified record."""

    @ids.lazy_identity(row_id=lambda record: "sha256:" + hashlib.sha256(
        repr((record.left, record.right)).encode("ascii")
    ).hexdigest())
    @dataclasses.dataclass(frozen=True, slots=True)
    class Row:
        left: int
        right: str
        row_id: str = dataclasses.field(init=False, compare=False, repr=False)

    return Row


def test_lazy_identity_is_not_computed_at_construction():
    Row = _build_lazy_pair()
    row = Row(1, "a")
    # The slot is still empty: nothing hashed while the record was built.
    assert ids.lazy_identity_is_pending(row, "row_id") is True
    minted = row.row_id
    assert minted.startswith("sha256:")
    assert ids.lazy_identity_is_pending(row, "row_id") is False


def test_lazy_identity_is_stable_for_the_object_lifetime():
    Row = _build_lazy_pair()
    row = Row(2, "b")
    assert row.row_id is row.row_id


def test_lazy_identity_field_is_rejected_from_the_constructor():
    Row = _build_lazy_pair()
    with pytest.raises(TypeError):
        Row(1, "a", "sha256:" + "0" * 64)


def test_lazy_identity_is_excluded_from_equality_and_hash():
    Row = _build_lazy_pair()
    first = Row(3, "c")
    second = Row(3, "c")
    assert first == second
    assert hash(first) == hash(second)
    # Equality must not have demanded the identity of either operand.
    assert ids.lazy_identity_is_pending(first, "row_id") is True
    assert ids.lazy_identity_is_pending(second, "row_id") is True


def test_lazy_identity_requires_a_non_init_non_compare_field():
    with pytest.raises(TypeError):

        @ids.lazy_identity(row_id=lambda record: "sha256:" + "0" * 64)
        @dataclasses.dataclass(frozen=True, slots=True)
        class Bad:
            left: int
            row_id: str = "sha256:" + "0" * 64


def test_lazy_identity_rejects_an_unknown_field_name():
    with pytest.raises(TypeError):

        @ids.lazy_identity(nope=lambda record: "sha256:" + "0" * 64)
        @dataclasses.dataclass(frozen=True, slots=True)
        class Bad:
            left: int


def test_unknown_attribute_still_raises_attribute_error():
    Row = _build_lazy_pair()
    row = Row(4, "d")
    with pytest.raises(AttributeError):
        row.definitely_not_a_field


# ------------------------------------------------- differential: records ---
def _real_records():
    """Return ``(name, record, schema, identity field)`` for real records."""

    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.ids import (
        _claim_factory, _evidence_factory, _subject_factory,
    )
    from tests.unit.transforms.unflatten_authority.helpers import (
        authority_id, block_ref,
    )

    ref = block_ref("lazy-identity")
    locator = model.BlockSubjectLocator(ref, 0x1000)
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=ref,
        anchor_ea=0x1000,
        locator=locator,
    )
    claim = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=subject,
        step_index=0,
        host_ea=0x1000,
        host_opcode=1,
        alias_token="alias",
        base_token="base",
        host_text_sha1=None,
        value_size=None,
        step_digest=authority_id("step"),
        source_generation=0,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence,
        kind=model.AuthorityEvidenceKind.REACHABILITY,
        subject=subject,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        payload=model.ReachabilityEvidencePayload(
            subject.subject_id, subject.subject_id, True, (subject.subject_id,),
        ),
    )
    return (
        ("claim", claim, ids.CLAIM_SCHEMA, "claim_id"),
        ("evidence", evidence, ids.EVIDENCE_SCHEMA, "evidence_id"),
    )


def test_demanded_record_ids_equal_the_eager_algorithm():
    """Acceptance B, unit half: the demanded ID is the pre-change ID."""

    for name, record, schema, field in _real_records():
        assert getattr(record, field) == eager_content_id(schema, record, field), name


def test_subject_id_is_the_eager_subject_fingerprint():
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.ids import _subject_factory
    from tests.unit.transforms.unflatten_authority.helpers import block_ref

    ref = block_ref("lazy-subject")
    locator = model.BlockSubjectLocator(ref, 0x2000)
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=ref,
        anchor_ea=0x2000,
        locator=locator,
    )
    # The eager algorithm for a subject is content_id over exactly the triple.
    preimage = ids._PREFIX + ids.SUBJECT_SCHEMA.encode("ascii") + b"\0" + ids.canonical_bytes(
        (subject.kind, subject.role, subject.locator)
    )
    assert subject.subject_id == "sha256:" + hashlib.sha256(preimage).hexdigest()


def test_records_are_built_without_demanding_any_identity():
    """Acceptance A, unit half: construction leaves every slot empty."""

    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.ids import (
        _claim_factory, _subject_factory,
    )
    from tests.unit.transforms.unflatten_authority.helpers import (
        authority_id, block_ref,
    )

    ref = block_ref("lazy-pending")
    locator = model.BlockSubjectLocator(ref, 0x3000)
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=ref,
        anchor_ea=0x3000,
        locator=locator,
    )
    assert ids.lazy_identity_is_pending(subject, "subject_id") is True
    claim = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=subject,
        step_index=0,
        host_ea=0x1000,
        host_opcode=1,
        alias_token="alias",
        base_token="base",
        host_text_sha1=None,
        value_size=None,
        step_digest=authority_id("step"),
        source_generation=0,
    )
    # Building the claim did not demand the subject's ID either.
    assert ids.lazy_identity_is_pending(claim, "claim_id") is True
    assert ids.lazy_identity_is_pending(subject, "subject_id") is True


def test_record_equality_is_structural_without_demanding_the_identity():
    """Constraint 4, on three real record types."""

    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.ids import (
        _claim_factory, _evidence_factory, _subject_factory,
    )
    from tests.unit.transforms.unflatten_authority.helpers import (
        authority_id, block_ref,
    )

    def build():
        ref = block_ref("lazy-eq")
        locator = model.BlockSubjectLocator(ref, 0x4000)
        subject = _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.EFFECT_SITE,
            block_ref=ref,
            anchor_ea=0x4000,
            locator=locator,
        )
        claim = _claim_factory(
            model.LocalAliasEffectScalarizationClaim,
            kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
            owner_subject=subject,
            step_index=0,
            host_ea=0x1000,
            host_opcode=1,
            alias_token="alias",
            base_token="base",
            host_text_sha1=None,
            value_size=None,
            step_digest=authority_id("step"),
            source_generation=0,
        )
        evidence = _evidence_factory(
            model.AuthorityEvidence,
            kind=model.AuthorityEvidenceKind.REACHABILITY,
            subject=subject,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            payload=model.ReachabilityEvidencePayload(
                "sha256:" + "1" * 64, "sha256:" + "2" * 64, True,
                ("sha256:" + "3" * 64,),
            ),
        )
        return subject, claim, evidence

    first = build()
    second = build()
    for left, right, field in zip(
        first, second, ("subject_id", "claim_id", "evidence_id")
    ):
        assert left == right
        assert hash(left) == hash(right)
        assert ids.lazy_identity_is_pending(left, field) is True
        assert ids.lazy_identity_is_pending(right, field) is True
        # ... and same content really does mean same ID.
        assert getattr(left, field) == getattr(right, field)
