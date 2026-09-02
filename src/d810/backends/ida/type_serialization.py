"""Single exact serialization authority for live IDA type metadata."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "SerializedTinfoParts",
    "apply_serialized_tinfo",
    "capture_serialized_tinfo",
    "const_candidate_semantically_matches",
    "const_variant_is_lossless",
    "deserialize_tinfo",
    "is_named_record_for_const_canonicalization",
    "serialize_tinfo",
    "tinfo_semantically_equal",
]


@dataclass(frozen=True, slots=True)
class SerializedTinfoParts:
    type_bytes: bytes
    field_bytes: bytes | None
    field_comment_bytes: bytes | None

    def __post_init__(self) -> None:
        if not isinstance(self.type_bytes, bytes) or not self.type_bytes:
            raise ValueError("type_bytes must be non-empty bytes")
        if self.field_bytes is not None and not isinstance(self.field_bytes, bytes):
            raise TypeError("field_bytes must be bytes or None")
        if self.field_comment_bytes is not None and not isinstance(
            self.field_comment_bytes, bytes
        ):
            raise TypeError("field_comment_bytes must be bytes or None")


def is_named_record_for_const_canonicalization(
    *,
    is_struct: bool,
    is_union: bool,
    is_anonymous: bool,
    type_name: str,
    is_imported_function_pointer: bool = False,
) -> bool:
    """Whether a parsed const spelling is warranted for this imported shape."""
    named_record = (
        (is_struct or is_union)
        and not is_anonymous
        and isinstance(type_name, str)
        and bool(type_name.strip())
    )
    return bool(named_record or is_imported_function_pointer)


def const_variant_is_lossless(
    before: SerializedTinfoParts,
    after: SerializedTinfoParts,
    *,
    before_size: int,
    after_size: int,
    before_name: str,
    after_name: str,
) -> bool:
    """Require a parsed candidate to differ only by IDA's const modifier."""
    if int(before_size) != int(after_size) or before_name != after_name:
        return False
    if (
        before.field_bytes != after.field_bytes
        or before.field_comment_bytes != after.field_comment_bytes
        or len(before.type_bytes) != len(after.type_bytes)
    ):
        return False
    differences = [
        (index, left, right)
        for index, (left, right) in enumerate(zip(before.type_bytes, after.type_bytes))
        if left != right
    ]
    if len(differences) != 1:
        return False
    index, before_byte, after_byte = differences[0]
    return (
        index == 0
        and not (before_byte & 0x40)
        and bool(after_byte & 0x40)
        and before_byte ^ after_byte == 0x40
    )


def tinfo_semantically_equal(left: object, right: object) -> bool:
    """Compare tinfo objects through public semantic comparison APIs."""
    equals_to = getattr(left, "equals_to", None)
    reverse_equals_to = getattr(right, "equals_to", None)
    if callable(equals_to) and callable(reverse_equals_to):
        try:
            return bool(equals_to(right)) and bool(reverse_equals_to(left))
        except (AttributeError, TypeError, RuntimeError):
            pass
    compare_with = getattr(left, "compare_with", None)
    reverse_compare_with = getattr(right, "compare_with", None)
    if callable(compare_with) and callable(reverse_compare_with):
        try:
            return bool(compare_with(right, 0)) and bool(reverse_compare_with(left, 0))
        except (AttributeError, TypeError, RuntimeError):
            pass
    return False


def const_candidate_semantically_matches(
    source: object,
    parsed_nonconst: object,
    direct_const: object,
    parsed_const: object,
) -> bool:
    """Require parser canonicalization to preserve both semantic variants."""
    return tinfo_semantically_equal(source, parsed_nonconst) and tinfo_semantically_equal(
        direct_const, parsed_const
    )


def serialize_tinfo(tif: object) -> SerializedTinfoParts:
    """Serialize all three IDA type components without lossy rendering."""

    serialized = tif.serialize()
    if not isinstance(serialized, tuple) or len(serialized) != 3:
        raise RuntimeError("tinfo_t.serialize() did not return three components")
    type_bytes, field_bytes, field_comment_bytes = serialized
    if not isinstance(type_bytes, bytes) or not type_bytes:
        raise RuntimeError("tinfo_t.serialize() returned invalid type bytes")
    return SerializedTinfoParts(
        type_bytes=type_bytes,
        field_bytes=None if field_bytes is None else bytes(field_bytes),
        field_comment_bytes=(
            None if field_comment_bytes is None else bytes(field_comment_bytes)
        ),
    )


def deserialize_tinfo(parts: SerializedTinfoParts):
    """Recreate one ``tinfo_t`` from the exact serialized components."""

    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if not tif.deserialize(
        None,
        parts.type_bytes,
        parts.field_bytes,
        parts.field_comment_bytes,
    ):
        raise RuntimeError("tinfo_t.deserialize() rejected serialized type")
    return tif


def capture_serialized_tinfo(ea: int) -> SerializedTinfoParts | None:
    """Capture an exact live type, representing absence as ``None``."""

    import ida_nalt
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, int(ea)) or tif.empty():
        return None
    return serialize_tinfo(tif)


def apply_serialized_tinfo(ea: int, parts: SerializedTinfoParts | None) -> bool:
    """Apply an exact type or restore exact absence, then verify readback."""

    import ida_nalt
    import ida_typeinf

    if parts is None:
        ida_nalt.del_tinfo(int(ea))
    else:
        tif = deserialize_tinfo(parts)
        if not ida_typeinf.apply_tinfo(int(ea), tif, ida_typeinf.TINFO_DEFINITE):
            # ``apply_tinfo`` can reject an existing structured data item even
            # when the same exact tinfo is valid.  ``set_tinfo`` is IDA's
            # public direct metadata setter for that narrow case.  Exact
            # serialized read-back below remains the acceptance criterion.
            ida_nalt.set_tinfo(int(ea), tif)
            # Re-apply once so IDA refreshes canonical metadata before the
            # exact read-back check.
            ida_typeinf.apply_tinfo(int(ea), tif, ida_typeinf.TINFO_DEFINITE)
    return capture_serialized_tinfo(int(ea)) == parts
