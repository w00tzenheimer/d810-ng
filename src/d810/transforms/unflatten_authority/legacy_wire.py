"""Closed lossless binary transport for legacy metadata values.

The wire domain is an exact builtin value tree.  Mutable containers are
identity-sensitive: repeated list/dict objects are rejected because this
transport preserves values and shapes, not object aliases.  Both directions
enforce ``MAX_LEGACY_WIRE_DEPTH`` before recursive descent.
"""

from __future__ import annotations

import struct


_NONE, _BOOL, _INT, _FLOAT, _STR, _BYTES, _LIST, _TUPLE, _DICT = range(9)
# A bounded value tree keeps hostile legacy payloads a typed rejection rather
# than allowing Python recursion limits to escape through a public boundary.
MAX_LEGACY_WIRE_DEPTH = 128


def _length(value: int) -> bytes:
    if type(value) is not int or value < 0:
        raise ValueError("length must be a non-negative exact int")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    start = pos
    for _ in range(10):
        if pos >= len(data):
            raise ValueError("truncated length")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if pos - start > 1 and byte == 0:
                raise ValueError("nonminimal length")
            if pos - start > 1 and value < 1 << (7 * (pos - start - 1)):
                raise ValueError("nonminimal length")
            return value, pos
        shift += 7
    raise ValueError("length is too long")


def _encode(value: object, seen: set[int], depth: int) -> bytes:
    if depth > MAX_LEGACY_WIRE_DEPTH:
        raise ValueError("legacy wire nesting depth exceeds limit")
    if value is None:
        return bytes((_NONE,))
    if type(value) is bool:
        return bytes((_BOOL, 1 if value else 0))
    if type(value) is int:
        sign = 1 if value < 0 else 0
        magnitude = abs(value)
        raw = b"" if magnitude == 0 else magnitude.to_bytes((magnitude.bit_length() + 7) // 8, "big")
        return bytes((_INT, sign)) + _length(len(raw)) + raw
    if type(value) is float:
        return bytes((_FLOAT,)) + struct.pack(">d", value)
    if type(value) is str:
        raw = value.encode("utf-8", "surrogatepass")
        return bytes((_STR,)) + _length(len(raw)) + raw
    if type(value) is bytes:
        return bytes((_BYTES,)) + _length(len(value)) + value
    if type(value) in (list, tuple):
        if type(value) is list:
            marker = id(value)
            if marker in seen:
                raise ValueError("shared or cyclic legacy value")
            seen.add(marker)
        body = b"".join(_encode(item, seen, depth + 1) for item in value)
        tag = _LIST if type(value) is list else _TUPLE
        return bytes((tag,)) + _length(len(value)) + body
    if type(value) is dict:
        marker = id(value)
        if marker in seen:
            raise ValueError("shared or cyclic legacy value")
        seen.add(marker)
        parts: list[bytes] = []
        for key, item in value.items():
            try:
                hash(key)
            except (TypeError, ValueError) as exc:
                raise TypeError("legacy dict key must be hashable") from exc
            parts.extend((_encode(key, seen, depth + 1), _encode(item, seen, depth + 1)))
        return bytes((_DICT,)) + _length(len(value)) + b"".join(parts)
    raise TypeError("legacy wire accepts only exact closed builtin types")


def encode_legacy_value(value: object) -> bytes:
    return _encode(value, set(), 0)


def _decode(data: bytes, pos: int, depth: int) -> tuple[object, int]:
    if depth > MAX_LEGACY_WIRE_DEPTH:
        raise ValueError("legacy wire nesting depth exceeds limit")
    if pos >= len(data):
        raise ValueError("truncated legacy value")
    tag = data[pos]
    pos += 1
    if tag == _NONE:
        return None, pos
    if tag == _BOOL:
        if pos >= len(data) or data[pos] not in (0, 1):
            raise ValueError("invalid bool")
        return bool(data[pos]), pos + 1
    if tag == _INT:
        if pos >= len(data) or data[pos] not in (0, 1):
            raise ValueError("invalid integer sign")
        sign = data[pos]
        size, pos = _read_length(data, pos + 1)
        end = pos + size
        if end > len(data):
            raise ValueError("truncated integer")
        raw = data[pos:end]
        if raw and raw[0] == 0:
            raise ValueError("nonminimal integer")
        magnitude = int.from_bytes(raw, "big")
        if magnitude == 0 and sign:
            raise ValueError("negative zero integer")
        return (-magnitude if sign else magnitude), end
    if tag == _FLOAT:
        end = pos + 8
        if end > len(data):
            raise ValueError("truncated float")
        return struct.unpack(">d", data[pos:end])[0], end
    if tag in (_STR, _BYTES):
        size, pos = _read_length(data, pos)
        end = pos + size
        if end > len(data):
            raise ValueError("truncated scalar")
        raw = data[pos:end]
        if tag == _STR:
            try:
                return raw.decode("utf-8", "surrogatepass"), end
            except UnicodeDecodeError as exc:
                raise ValueError("invalid UTF-8") from exc
        return raw, end
    if tag in (_LIST, _TUPLE):
        count, pos = _read_length(data, pos)
        items: list[object] = []
        for _ in range(count):
            item, pos = _decode(data, pos, depth + 1)
            items.append(item)
        return (items if tag == _LIST else tuple(items)), pos
    if tag == _DICT:
        count, pos = _read_length(data, pos)
        result: dict[object, object] = {}
        for _ in range(count):
            key, pos = _decode(data, pos, depth + 1)
            try:
                if key in result:
                    raise ValueError("duplicate legacy dict key")
                hash(key)
            except TypeError as exc:
                raise ValueError("unhashable legacy dict key") from exc
            item, pos = _decode(data, pos, depth + 1)
            result[key] = item
        return result, pos
    raise ValueError("unknown legacy wire tag")


def decode_legacy_value(data: bytes) -> object:
    if type(data) is not bytes or not data:
        raise TypeError("legacy wire input must be non-empty exact bytes")
    value, pos = _decode(data, 0, 0)
    if pos != len(data):
        raise ValueError("trailing legacy wire bytes")
    if encode_legacy_value(value) != data:
        raise ValueError("noncanonical legacy wire")
    return value


__all__ = ["MAX_LEGACY_WIRE_DEPTH", "decode_legacy_value", "encode_legacy_value"]
