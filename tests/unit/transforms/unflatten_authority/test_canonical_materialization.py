"""Live records validate semantic fields; boundaries materialise canonical bytes.

The two operations under test are the halves of the dual identity as the
2026-09-05 ruling states it: a live internal record validates its semantic
fields and computes no SHA-256, no wire tree and no JSON, while an explicit
``materialize_for_persistence`` builds the canonical representation at a named
boundary.  Byte identity with the representation the same input produced
before that boundary existed is the hard requirement here, so every test that
touches bytes compares against ``canonical_bytes``/``validate_canonical_roundtrip``
directly rather than against a stored literal.
"""

from __future__ import annotations

import json

import pytest

from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.transforms.cfg_transaction import NativeBlockRef, PlanBlockRef
from d810.transforms.unflatten_authority import canonical_session
from d810.transforms.unflatten_authority import ids as authority_ids
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.canonical_session import (
    CanonicalSessionPhase,
    CanonicalWorkMetrics,
    _WorkLedger,
    _canonical_validation_session,
    process_work_metrics,
)
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key(function_rva=0x2000)


@pytest.fixture(autouse=True)
def _isolated_process_ledger(monkeypatch):
    """Swap in a private ledger so these tests never disturb process totals."""

    monkeypatch.setattr(canonical_session, "_PROCESS_LEDGER", _WorkLedger())
    yield


def _native_ref(ea: int = 0x2000) -> NativeBlockRef:
    return NativeBlockRef(
        StableBlockIdentity.from_intervals(
            (NativeEaInterval(ea, ea + 0x10),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(ea,),
        ),
    )


def _subject(anchor_ea: int = 0x2000) -> model.SemanticSubjectRef:
    block_ref = PlanBlockRef("sha256:" + "2" * 64, "helper")
    return authority_ids._subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.PLANNED_HELPER,
        block_ref=block_ref,
        anchor_ea=anchor_ea,
        locator=model.BlockSubjectLocator(block_ref, anchor_ea),
    )


@pytest.mark.parametrize("build", (_native_ref, _subject))
def test_materialisation_is_byte_identical_to_the_representation_it_replaces(
    build,
) -> None:
    """The boundary must not move a single canonical byte.

    ``materialize_for_persistence`` is the same encode, the same decode and
    the same strict comparison ``validate_canonical_roundtrip`` performs; the
    only difference is that it is now an act a caller performs at a named
    boundary rather than work every construction pays for.
    """

    value = build()
    expected_bytes = authority_ids.canonical_bytes(value)
    expected_record = authority_ids.validate_canonical_roundtrip(value, type(value))

    materialised = authority_ids.materialize_for_persistence(value, type(value))

    assert materialised.canonical_bytes == expected_bytes
    assert materialised.record == expected_record
    assert materialised.record == value
    assert type(materialised.record) is type(value)
    assert authority_ids.canonical_decode(materialised.canonical_bytes) == value


def test_materialisation_keeps_the_strict_decode_it_inherited() -> None:
    """A value that does not decode back to its own type is still refused."""

    value = _native_ref()
    with pytest.raises(ValueError, match="canonical roundtrip changed"):
        authority_ids.materialize_for_persistence(value, PlanBlockRef)


def test_materialisation_refuses_a_value_with_no_canonical_encoding() -> None:
    with pytest.raises(TypeError, match="no canonical encoding"):
        authority_ids.materialize_for_persistence(object(), object)


def test_the_materialising_flag_is_set_only_inside_the_boundary(monkeypatch) -> None:
    """The flag is what a proof test reads; it must be exact, not approximate."""

    observed: list[bool] = []
    real = authority_ids.canonical_bytes

    def _probe(value, **kwargs):
        observed.append(authority_ids.materializing())
        return real(value, **kwargs)

    monkeypatch.setattr(authority_ids, "canonical_bytes", _probe)

    assert authority_ids.materializing() is False
    authority_ids.materialize_for_persistence(_native_ref(), NativeBlockRef)
    assert authority_ids.materializing() is False
    # Two, because the decode half re-encodes to prove the bytes canonical;
    # both are inside the boundary and that is the whole assertion.
    assert observed == [True, True]


def test_the_materialising_flag_survives_a_refused_materialisation() -> None:
    """A refusal must not leave the flag armed for the rest of the phase."""

    with pytest.raises(ValueError, match="canonical roundtrip changed"):
        authority_ids.materialize_for_persistence(_native_ref(), PlanBlockRef)
    assert authority_ids.materializing() is False


@pytest.mark.parametrize("build", (_native_ref, _subject))
def test_live_validation_encodes_nothing(build, monkeypatch) -> None:
    """The live half must not reach any canonical representation at all.

    Every encoding entry point is armed to raise, so the test cannot pass by
    accident: if ``validate_live_semantic_fields`` ever built a wire tree,
    JSON, canonical bytes or a decode, this fails.
    """

    value = build()

    def _forbidden(*args, **kwargs):
        raise AssertionError("live validation must not canonicalise")

    for name in (
        "_wire", "_external_wire", "_json_bytes", "canonical_bytes",
        "canonical_decode", "content_id", "_record_content_id",
    ):
        monkeypatch.setattr(authority_ids, name, _forbidden)
    monkeypatch.setattr(json, "dumps", _forbidden)

    assert authority_ids.validate_live_semantic_fields(value, type(value)) is None


def test_live_validation_still_refuses_a_foreign_type() -> None:
    with pytest.raises(TypeError, match="expected PlanBlockRef, got NativeBlockRef"):
        authority_ids.validate_live_semantic_fields(_native_ref(), PlanBlockRef)


def test_live_validation_still_refuses_an_unencodable_value() -> None:
    with pytest.raises(TypeError, match="no canonical encoding"):
        authority_ids.validate_live_semantic_fields((object(),), tuple)


def test_live_validation_costs_one_deep_validation_and_no_encoding() -> None:
    """Counters, not timings: the live half is exactly one recursive walk."""

    value = _native_ref()
    before = process_work_metrics()
    authority_ids.validate_live_semantic_fields(value, NativeBlockRef)
    delta = process_work_metrics().delta(before)

    assert delta.deep_validations == 1
    assert delta.wire_encodes == 0
    assert delta.roundtrip_decodes == 0
    assert delta.content_id_mints == 0
    assert delta.materializations == 0
    assert delta.occurrence_stamps == 0
    assert delta.bytes_lookup_hits == 0
    assert delta.bytes_lookup_misses == 0


def test_a_materialisation_is_counted_exactly_once() -> None:
    value = _native_ref()
    before = process_work_metrics()
    authority_ids.materialize_for_persistence(value, NativeBlockRef)
    delta = process_work_metrics().delta(before)

    assert delta.materializations == 1
    assert delta.roundtrip_decodes == 1
    assert delta.wire_encodes >= 1


def test_a_refused_materialisation_is_not_counted() -> None:
    with pytest.raises(ValueError, match="canonical roundtrip changed"):
        authority_ids.materialize_for_persistence(_native_ref(), PlanBlockRef)
    assert process_work_metrics().materializations == 0


def test_content_id_mints_are_attributed_to_the_session_and_the_process() -> None:
    """Every fresh SHA-256 over canonical bytes is now attributable."""

    value = _native_ref()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        authority_ids.content_id(authority_ids.SUBJECT_SCHEMA, value)
        authority_ids.content_id(authority_ids.SUBJECT_SCHEMA, value)
        assert session.metrics.content_id_mints == 2
    assert process_work_metrics().content_id_mints == 2


def test_the_new_counters_are_exact_ints_like_every_other_counter() -> None:
    assert CanonicalWorkMetrics(content_id_mints=3).content_id_mints == 3
    assert CanonicalWorkMetrics(materializations=3).materializations == 3
    with pytest.raises(TypeError):
        CanonicalWorkMetrics(content_id_mints=True)
    with pytest.raises(TypeError):
        CanonicalWorkMetrics(materializations=-1)
