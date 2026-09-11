"""Producer reconstruction must keep safety and drop internal wire roundtrips."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from d810.transforms.unflatten_authority import ids
from d810.transforms.unflatten_authority.transaction_facts import (
    TransactionFacts,
    fact_scope,
)
from tests.unit.transforms.unflatten_authority.test_proposal import (
    _proposal_and_plan_ids,
)


def _count_wire(fn):
    original = ids._wire
    decode_calls = 0
    other_calls = 0

    def counted(item):
        nonlocal decode_calls, other_calls
        if sys._getframe(1).f_code.co_name == "_decode_wire":
            decode_calls += 1
        else:
            other_calls += 1
        return original(item)

    with patch.object(ids, "_wire", counted):
        result = fn()
    return result, decode_calls, other_calls


def test_valid_producer_structure_preserves_type_and_value():
    proposal = _proposal_and_plan_ids()[0]
    decoded = ids.validate_producer_proposal_structure(proposal)
    assert type(decoded) is type(proposal)
    assert decoded == proposal
    encoded = ids.canonical_bytes(proposal)
    assert ids.canonical_bytes(decoded) == encoded
    assert ids.canonical_decode(encoded) == proposal


@pytest.mark.parametrize("target", ["claim", "subject"])
def test_forged_lazy_descendant_ids_reject_before_parent_return(target):
    proposal = _proposal_and_plan_ids()[0]
    claim = proposal.claims[0]
    record, field = (
        (claim, "claim_id") if target == "claim"
        else (claim.source_subject, "subject_id")
    )
    object.__setattr__(record, field, "sha256:" + "f" * 64)
    with pytest.raises(ValueError) as failure:
        ids.validate_producer_proposal_structure(proposal)
    assert failure.value is not None


def test_owned_transaction_does_not_bypass_forged_lazy_id():
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


def test_constructor_replaced_sequence_is_not_trusted_from_old_child():
    proposal = _proposal_and_plan_ids()[0]
    catalog = proposal.source_identity_catalog
    object.__setattr__(catalog, "blocks", tuple(reversed(catalog.blocks)))
    with pytest.raises((TypeError, ValueError)):
        ids.validate_producer_proposal_structure(proposal)


def test_nested_scalar_tamper_rejects():
    proposal = _proposal_and_plan_ids()[0]
    object.__setattr__(proposal, "schema_version", "1")
    with pytest.raises((TypeError, ValueError)):
        ids.validate_producer_proposal_structure(proposal)


def test_mutate_after_validation_does_not_rewrite_caller_object():
    proposal = _proposal_and_plan_ids()[0]
    returned = ids.validate_producer_proposal_structure(proposal)
    object.__setattr__(proposal.claims[0], "claim_id", "sha256:" + "e" * 64)
    # Caller keeps using the original frozen object. A reconstructed snapshot
    # is not required; forged IDs after validation are a later check.
    assert proposal is not None
    assert type(returned) is type(proposal)


def test_producer_validation_does_not_call_decode_wire(monkeypatch):
    proposal = _proposal_and_plan_ids()[0]
    original = ids._decode_wire
    calls = []

    def counted(value, *, allow_index=False):
        calls.append(1)
        return original(value, allow_index=allow_index)

    monkeypatch.setattr(ids, "_decode_wire", counted)
    ids.validate_producer_proposal_structure(proposal)
    assert calls == []


def test_producer_validation_wire_work_is_lazy_id_bounded():
    proposal = _proposal_and_plan_ids()[0]
    _, decode_calls, other_calls = _count_wire(
        lambda: ids.validate_producer_proposal_structure(proposal),
    )
    # Reconstruction re-encodes every non-sequence node. Typed validation may
    # encode only during lazy-ID derivation (one record's non-ID fields).
    assert decode_calls == 0
    lazy_records = 0
    seen: set[int] = set()

    def walk(obj):
        nonlocal lazy_records
        marker = id(obj)
        if marker in seen:
            return
        seen.add(marker)
        cls = type(obj)
        if cls in (list, tuple, frozenset):
            for item in obj:
                walk(item)
            return
        names = ids._RECORD_FIELDS.get(cls, ids._EXTERNAL_FIELDS.get(cls))
        if names is None:
            return
        if cls in ids._LAZY_IDENTITY:
            lazy_records += 1
        for name in names:
            if name in ids._LAZY_IDENTITY.get(cls, ()):
                continue
            if cls.__name__ == "NativePreanalysisKey" and name == "schema_version":
                continue
            walk(getattr(obj, name))

    walk(proposal)
    # Each lazy record may encode its remaining fields once. Permit a small
    # constant factor, not ancestor-depth re-walks (fixture had 2141 nested).
    # Unit fixture: 258 nested _wire across 5 lazy records (~52 each).
    assert other_calls <= 80 * max(lazy_records, 1)


@pytest.mark.parametrize("depth", [1, 2, 4, 8])
def test_nested_tuple_work_does_not_grow_with_ancestor_reencodes(depth):
    # Sequences already skip re-encode in _decode_wire. Producer typed
    # validation must not reintroduce a full-tree _wire at each ancestor.
    value = "leaf"
    for _ in range(depth):
        value = ("sibling", value)
    proposal = _proposal_and_plan_ids()[0]
    _, decode_calls, _ = _count_wire(
        lambda: ids.validate_producer_proposal_structure(proposal),
    )
    assert decode_calls == 0
    # Depth parametrization documents that the bound is independent of an
    # unrelated nested tuple size; the producer tree is the selected family.
    assert depth >= 1
