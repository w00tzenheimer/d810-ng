"""Local child-encoding reuse must never weaken decode publication guards.

The decoder may skip re-encoding an *audited* record's descendants only when
the constructor provably left those descendants alone.  ``is`` alone is not
proof: a constructor can mutate a nested descendant and keep its identity.
These tests pin the audited family, the shape check that stands in for the
proof, the fallback for genuinely changed children, and the pre-existing
malformed / forged-identity guards.
"""

import json
from unittest.mock import patch

import pytest

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import (
    NativeBlockRef,
    NativeEaInterval,
    NativeEaIntervalSet,
    StableBlockIdentity,
)
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority import ids


def _native_key() -> NativePreanalysisKey:
    return NativePreanalysisKey(
        input_identity="input:test",
        processor="metapc",
        bitness=64,
        function_rva=0x1000,
        function_fingerprint="sha256:" + "a" * 64,
        profile_fingerprint="sha256:" + "b" * 64,
        sdk_fingerprint="sha256:" + "c" * 64,
    )


def _audited_fixtures() -> list[tuple[str, object]]:
    key = _native_key()
    identity = StableBlockIdentity.from_instruction_eas(
        [0x1000, 0x1004], native_key=key,
    )
    return [
        ("NativeEaInterval", NativeEaInterval(0x10, 0x20)),
        (
            "NativeEaIntervalSet",
            NativeEaIntervalSet.from_intervals([NativeEaInterval(0x10, 0x20)]),
        ),
        ("StableBlockIdentity", identity),
        ("NativeBlockRef", NativeBlockRef(identity)),
        ("LogicalBlockRef", LogicalBlockRef("session:1", "token:1", 3)),
    ]


def _count_wire_calls(encoded: bytes) -> int:
    calls = 0
    original = ids._wire

    def counted(item):
        nonlocal calls
        calls += 1
        return original(item)

    saved = ids._wire
    ids._wire = counted
    try:
        ids.canonical_decode(encoded)
    finally:
        ids._wire = saved
    return calls


def _interval_wire(start: int, end: int) -> dict:
    return {
        "t": "record",
        "n": "NativeEaInterval",
        "v": [
            ["start_ea", {"t": "int", "v": str(start)}],
            ["end_ea", {"t": "int", "v": str(end)}],
        ],
    }


def _interval_set_wire(ranges: list[tuple[int, int]]) -> dict:
    return {
        "t": "record",
        "n": "NativeEaIntervalSet",
        "v": [["intervals", {"t": "tuple", "v": [_interval_wire(a, b) for a, b in ranges]}]],
    }


def test_audited_family_eliminates_descendant_rewalk():
    """Reuse must remove traversal, not merely move it.

    The control disables the audited set and pays the full ancestor re-encode.
    A strict inequality keeps this a work-elimination claim rather than a
    fixed budget that could be met by a no-op.
    """
    ids._ensure_registries()
    fixtures = _audited_fixtures()
    saved = ids._AUDITED_LOCAL_RECORD_TYPES
    eliminated = {}
    try:
        for name, value in fixtures:
            encoded = ids.canonical_bytes(value)
            audited = _count_wire_calls(encoded)
            decoded = ids.canonical_decode(encoded)
            assert decoded == value
            assert ids.canonical_bytes(decoded) == encoded

            ids._AUDITED_LOCAL_RECORD_TYPES = frozenset()
            control = _count_wire_calls(encoded)
            ids._AUDITED_LOCAL_RECORD_TYPES = saved

            assert audited <= control, f"{name}: audited={audited} control={control}"
            eliminated[name] = control - audited
    finally:
        ids._AUDITED_LOCAL_RECORD_TYPES = saved

    # Records that embed the native key must actually drop descendant work.
    assert eliminated["StableBlockIdentity"] > 0
    assert eliminated["NativeBlockRef"] > 0


def test_audited_match_adds_no_encoding_of_its_own():
    """The replacement check is structural, not a second re-encode."""
    ids._ensure_registries()
    key = _native_key()
    identity = StableBlockIdentity.from_instruction_eas(
        [0x1000, 0x1004], native_key=key,
    )
    result = StableBlockIdentity(
        native_key=identity.native_key,
        exact_instruction_eas=identity.exact_instruction_eas,
        native_ranges=identity.native_ranges,
    )
    children = {
        "native_key": identity.native_key,
        "exact_instruction_eas": identity.exact_instruction_eas,
        "native_ranges": identity.native_ranges,
    }
    names = ("native_key", "exact_instruction_eas", "native_ranges")

    calls = 0
    original = ids._wire

    def counted(item):
        nonlocal calls
        calls += 1
        return original(item)

    saved = ids._wire
    ids._wire = counted
    try:
        accepted = ids._audited_record_matches_incoming(
            result, StableBlockIdentity, children, names,
        )
    finally:
        ids._wire = saved

    assert accepted is True
    assert calls == 0


def test_sequence_normalization_reuses_identical_children():
    """A rebuilt tuple with the same child objects is still the same content."""
    first = NativeEaInterval(0x10, 0x20)
    incoming = (first,)
    normalized = NativeEaIntervalSet(incoming)
    assert normalized.intervals is not incoming
    assert normalized.intervals[0] is first

    assert (
        ids._audited_record_matches_incoming(
            normalized,
            NativeEaIntervalSet,
            {"intervals": incoming},
            ("intervals",),
        )
        is True
    )


def test_reordered_children_fall_back_and_are_rejected():
    """Sorting changes the child order; the wire was not canonical."""
    # Non-adjacent ranges so canonicalisation reorders without merging.
    wire = _interval_set_wire([(0x2000, 0x2010), (0x1000, 0x1010)])
    with pytest.raises(ValueError) as failure:
        ids._decode_wire(wire)
    assert "non-canonical" in str(failure.value)


def test_merged_children_fall_back_and_are_rejected():
    """Adjacent children merge into a new interval; that is a content change."""
    wire = _interval_set_wire([(0x1000, 0x1010), (0x1010, 0x1020)])
    with pytest.raises(ValueError) as failure:
        ids._decode_wire(wire)
    assert "non-canonical" in str(failure.value)


def test_audited_set_is_disjoint_from_lazy_identities():
    """No audited record may take the fast path while carrying a derived ID.

    The supplied-ID byte check lives in the skipped re-encode, so a lazy
    identity must force the fallback.
    """
    ids._ensure_registries()
    assert ids._AUDITED_LOCAL_RECORD_TYPES.isdisjoint(ids._LAZY_IDENTITY)


def test_forged_lazy_identity_still_rejects_through_decode():
    """A tampered derived identity is rejected before publication."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticRouteProofKind,
    )
    from .test_bind import _compiler_corridor_unsupported_case

    ids._ensure_registries()
    authority, *_ = _compiler_corridor_unsupported_case(
        proof_kind=SemanticRouteProofKind.STATE_TRANSFORM,
    )
    wire = json.loads(ids.canonical_bytes(authority))

    lazy_pairs = {
        (record_type.__name__, field)
        for record_type, fields in ids._LAZY_IDENTITY.items()
        for field in fields
    }
    forged = {"t": "str", "v": "sha256:" + "f" * 64}

    stack = [wire]
    tampered = 0
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if item.get("t") == "record":
                name = item.get("n")
                fields = item.get("v")
                if isinstance(fields, list):
                    for pair in fields:
                        if (
                            isinstance(pair, list)
                            and len(pair) == 2
                            and (name, pair[0]) in lazy_pairs
                        ):
                            pair[1] = forged
                            tampered += 1
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)

    assert tampered > 0
    encoded = json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(ValueError) as failure:
        ids.canonical_decode(encoded)
    assert failure.value is not None


def test_malformed_child_rejects_before_publication():
    """A malformed child wire must fail even on the audited fast path."""
    wire = _interval_set_wire([(0x1000, 0x1010)])
    # Break the child's nonneg int encoding.
    wire["v"][0][1]["v"][0]["v"][0][1]["v"] = "+4096"
    with pytest.raises(ValueError) as failure:
        ids._decode_wire(wire)
    assert failure.value is not None


def test_malformed_child_never_constructs_the_parent():
    """Raising is not enough: no parent object may be built or validated.

    An exception after a partially built parent would still have published it.
    The parent's ``__post_init__`` is the observable side of construction.
    """
    calls = []
    original = NativeEaIntervalSet.__post_init__

    def spy(self):
        calls.append(self)
        return original(self)

    valid = _interval_set_wire([(0x1000, 0x1010)])
    malformed = _interval_set_wire([(0x1000, 0x1010)])
    malformed["v"][0][1]["v"][0]["v"][0][1]["v"] = "+4096"

    with patch.object(NativeEaIntervalSet, "__post_init__", spy):
        assert isinstance(ids._decode_wire(valid), NativeEaIntervalSet)
        assert len(calls) == 1  # positive control: the spy does observe it
        calls.clear()
        with pytest.raises(ValueError):
            ids._decode_wire(malformed)
        assert calls == []  # the parent was never materialised


def test_decoder_never_returns_a_value_that_does_not_reencode_to_its_wire():
    """The audited fast path must be indistinguishable from the re-encode.

    This states the constructor child-preservation guarantee executably: if
    ``_decode_wire`` returns rather than raising, the result must re-encode to
    exactly the wire that arrived.  Identity is never the proof; byte equality
    with the arriving wire is.
    """
    ids._ensure_registries()
    key = _native_key()
    cases = [
        ("canonical:" + name, json.loads(ids.canonical_bytes(value)))
        for name, value in _audited_fixtures()
    ]

    bool_start = _interval_wire(0x10, 0x20)
    bool_start["v"][0][1] = {"t": "bool", "v": True}
    cases.append(("bool-into-int-field", bool_start))

    as_list = _interval_set_wire([(0x1000, 0x1010)])
    as_list["v"][0][1] = {"t": "list", "v": as_list["v"][0][1]["v"]}
    cases.append(("list-for-tuple", as_list))

    cases.append(("reordered", _interval_set_wire([(0x2000, 0x2010), (0x1000, 0x1010)])))
    cases.append(("adjacent-merge", _interval_set_wire([(0x1000, 0x1010), (0x1010, 0x1020)])))

    ranges = NativeEaIntervalSet.from_intervals([NativeEaInterval(0, 0x10)])
    frozen = json.loads(
        ids.canonical_bytes(
            StableBlockIdentity(
                native_key=key,
                exact_instruction_eas=frozenset({1}),
                native_ranges=ranges,
            )
        )
    )
    for pair in frozen["v"]:
        if pair[0] == "exact_instruction_eas":
            pair[1] = {"t": "frozenset", "v": [{"t": "bool", "v": True}]}
    cases.append(("bool-in-frozenset", frozen))

    for label, wire in cases:
        snapshot = json.loads(json.dumps(wire, sort_keys=True))
        try:
            result = ids._decode_wire(wire)
        except (TypeError, ValueError):
            continue  # rejected outright: always safe
        reencoded = ids._wire(result)
        assert reencoded == snapshot, (
            f"{label}: decoder returned a value that does not re-encode to its "
            f"own wire\n  arrived:    {snapshot}\n  re-encoded: {reencoded}"
        )


def test_bool_is_not_reused_as_an_int_field():
    """``1 == True`` but the wire tags differ, so reuse would be a bypass."""
    wire = _interval_wire(0x10, 0x20)
    wire["v"][0][1] = {"t": "bool", "v": True}
    with pytest.raises(ValueError) as failure:
        ids._decode_wire(wire)
    assert "non-canonical" in str(failure.value)


def test_list_is_not_reused_as_a_tuple_field():
    """list and tuple are different container tags even with equal elements."""
    wire = _interval_set_wire([(0x1000, 0x1010)])
    wire["v"][0][1] = {"t": "list", "v": wire["v"][0][1]["v"]}
    with pytest.raises(ValueError) as failure:
        ids._decode_wire(wire)
    assert "non-canonical" in str(failure.value)


def test_bool_inside_frozenset_is_not_reused():
    """The constructor accepts this coercion, so the shape check is the guard."""
    key = _native_key()
    ranges = NativeEaIntervalSet.from_intervals([NativeEaInterval(0, 0x10)])
    # Negative control: construction succeeds and yields frozenset({1}).
    coerced = StableBlockIdentity(
        native_key=key,
        exact_instruction_eas=frozenset({True}),
        native_ranges=ranges,
    )
    assert coerced.exact_instruction_eas == frozenset({1})
    assert {type(ea) for ea in coerced.exact_instruction_eas} == {int}

    wire = json.loads(
        ids.canonical_bytes(
            StableBlockIdentity(
                native_key=key,
                exact_instruction_eas=frozenset({1}),
                native_ranges=ranges,
            )
        )
    )
    for pair in wire["v"]:
        if pair[0] == "exact_instruction_eas":
            pair[1] = {"t": "frozenset", "v": [{"t": "bool", "v": True}]}
    with pytest.raises(ValueError) as failure:
        ids._decode_wire(wire)
    assert "non-canonical" in str(failure.value)
