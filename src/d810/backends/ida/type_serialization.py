"""Single exact serialization authority for live IDA type metadata."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "SerializedTinfoParts",
    "apply_serialized_tinfo",
    "capture_serialized_tinfo",
    "deserialize_tinfo",
    "serialize_tinfo",
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
            return False
    return capture_serialized_tinfo(int(ea)) == parts
