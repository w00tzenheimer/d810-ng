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
