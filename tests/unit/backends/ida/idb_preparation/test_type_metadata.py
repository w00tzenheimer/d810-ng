from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from d810.backends.ida.idb_preparation.type_metadata import (
    IdaTypeMetadata,
    TypeMetadataInterference,
)
from d810.backends.ida.type_serialization import (
    SerializedTinfoParts,
    apply_serialized_tinfo,
    const_candidate_semantically_matches,
    const_variant_is_lossless,
    is_named_record_for_const_canonicalization,
)
from d810.capabilities.idb_preparation import SerializedTypeSnapshot

pytestmark = pytest.mark.pure_python


class _Types:
    def __init__(self, snapshot: SerializedTypeSnapshot) -> None:
        self.snapshot = snapshot
        self.applied: list[SerializedTypeSnapshot] = []

    def capture(self, item_ea: int) -> SerializedTypeSnapshot:
        return self.snapshot

    def apply(self, item_ea: int, snapshot: SerializedTypeSnapshot) -> bool:
        self.applied.append(snapshot)
        self.snapshot = snapshot
        return True


def _present(tag: bytes) -> SerializedTypeSnapshot:
    return SerializedTypeSnapshot.from_parts(
        b"type-" + tag,
        b"fields-" + tag,
        b"comments-" + tag,
    )


def test_restore_deletes_d810_created_type() -> None:
    before = SerializedTypeSnapshot.absent()
    after = _present(b"const-array")
    types = _Types(before)
    adapter = IdaTypeMetadata(
        capture_snapshot=types.capture,
        apply_snapshot=types.apply,
    )

    adapter.apply(0x500000, before, after)
    adapter.restore(0x500000, after, before)

    assert adapter.capture(0x500000) == before
    assert types.applied == [after, before]


def test_existing_three_component_type_round_trips_exactly() -> None:
    before = _present(b"struct")
    after = _present(b"const-struct")
    types = _Types(before)
    adapter = IdaTypeMetadata(
        capture_snapshot=types.capture,
        apply_snapshot=types.apply,
    )

    adapter.apply(0x500000, before, after)
    adapter.restore(0x500000, after, before)

    assert adapter.capture(0x500000).parts == before.parts


def test_apply_refuses_live_type_divergence_before_writing() -> None:
    expected = _present(b"expected")
    live = _present(b"user")
    types = _Types(live)
    adapter = IdaTypeMetadata(
        capture_snapshot=types.capture,
        apply_snapshot=types.apply,
    )

    with pytest.raises(TypeMetadataInterference, match="before-image"):
        adapter.apply(0x500000, expected, _present(b"const"))

    assert types.applied == []


def test_restore_refuses_user_edit_after_apply() -> None:
    before = _present(b"before")
    after = _present(b"after")
    types = _Types(before)
    adapter = IdaTypeMetadata(
        capture_snapshot=types.capture,
        apply_snapshot=types.apply,
    )
    adapter.apply(0x500000, before, after)
    user_edit = _present(b"user-edit")
    types.snapshot = user_edit

    with pytest.raises(TypeMetadataInterference, match="after-image"):
        adapter.restore(0x500000, after, before)

    assert types.snapshot == user_edit


def test_failed_backend_apply_never_reports_success() -> None:
    before = SerializedTypeSnapshot.absent()
    after = _present(b"const")
    adapter = IdaTypeMetadata(
        capture_snapshot=lambda ea: before,
        apply_snapshot=lambda ea, snapshot: False,
    )

    with pytest.raises(RuntimeError, match="failed to apply"):
        adapter.apply(0x500000, before, after)


def test_serialized_type_apply_falls_back_to_ida_nalt_set_tinfo(monkeypatch) -> None:
    """Existing structured items use IDA's direct metadata setter if needed."""

    class FakeTinfo:
        def __init__(self) -> None:
            self.parts = None

        def deserialize(self, _til, type_bytes, field_bytes, comment_bytes):
            self.parts = (type_bytes, field_bytes, comment_bytes)
            return True

        def serialize(self):
            return self.parts

        def empty(self):
            return self.parts is None

    parts = SerializedTinfoParts(b"structured-const", b"fields", None)
    calls: list[str] = []
    ida_typeinf = SimpleNamespace(
        tinfo_t=FakeTinfo,
        TINFO_DEFINITE=1,
        apply_tinfo=lambda ea, tif, flags: calls.append("apply") or False,
    )
    ida_nalt = SimpleNamespace(
        # IDAPython exposes this setter as a void-style wrapper on IDA 9.4.
        # The exact serialized read-back, not the wrapper return, decides
        # whether the write succeeded.
        set_tinfo=lambda ea, tif: calls.append("set"),
        get_tinfo=lambda tif, ea: setattr(
            tif,
            "parts",
            (parts.type_bytes, parts.field_bytes, parts.field_comment_bytes),
        )
        or True,
    )
    monkeypatch.setitem(sys.modules, "ida_typeinf", ida_typeinf)
    monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)

    assert apply_serialized_tinfo(0x500000, parts)
    assert calls == ["apply", "set", "apply"]


def test_const_parser_canonicalization_is_limited_to_lossless_record_shapes() -> None:
    assert not is_named_record_for_const_canonicalization(
        is_struct=True, is_union=False, is_anonymous=True, type_name="_CERTSTORE"
    )
    assert not is_named_record_for_const_canonicalization(
        is_struct=False, is_union=False, is_anonymous=False, type_name="DWORD"
    )
    assert is_named_record_for_const_canonicalization(
        is_struct=True, is_union=False, is_anonymous=False, type_name="_CERTSTORE"
    )

    before = SerializedTinfoParts(b"\x0a\x10", b"fields", b"comments")
    assert const_variant_is_lossless(
        before,
        SerializedTinfoParts(b"\x4a\x10", b"fields", b"comments"),
        before_size=16,
        after_size=16,
        before_name="_CERTSTORE",
        after_name="_CERTSTORE",
    )
    assert not const_variant_is_lossless(
        before,
        SerializedTinfoParts(b"\x4a\x11", b"fields", b"comments"),
        before_size=16,
        after_size=16,
        before_name="_CERTSTORE",
        after_name="_CERTSTORE",
    )


class _ComparableTinfo:
    def __init__(self, semantic: str) -> None:
        self.semantic = semantic

    def equals_to(self, other: object) -> bool:
        return isinstance(other, _ComparableTinfo) and self.semantic == other.semantic


def test_const_parser_canonicalization_requires_semantic_equivalence() -> None:
    assert not const_candidate_semantically_matches(
        _ComparableTinfo("source"),
        _ComparableTinfo("different"),
        _ComparableTinfo("const"),
        _ComparableTinfo("const"),
    )
    assert const_candidate_semantically_matches(
        _ComparableTinfo("source"),
        _ComparableTinfo("source"),
        _ComparableTinfo("const"),
        _ComparableTinfo("const"),
    )
