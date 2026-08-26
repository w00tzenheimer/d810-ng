"""Versioned JSON persistence for portable typed MBA terms."""

from __future__ import annotations

from collections.abc import Mapping

from d810.mba.typed_term import TypedBvTerm


TERM_WIRE_SCHEMA_VERSION = 1
_MAX_DECODER_DEPTH = 256
_TERM_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "width",
        "value",
        "leaf_key",
        "shift_count",
        "children",
    }
)


def _require_mapping(value: object, *, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be a mapping")
    return value  # type: ignore[return-value]


def _require_exact_fields(
    data: Mapping[str, object], expected: frozenset[str], *, context: str
) -> None:
    keys = set(data)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unknown " + ", ".join(str(item) for item in extra))
        raise ValueError(f"{context} has invalid fields: {'; '.join(details)}")


def _encode_leaf_key_part(value: object) -> dict[str, object]:
    if value is None:
        return {"kind": "none"}
    if type(value) is bool:
        return {"kind": "bool", "value": value}
    if type(value) is int:
        return {"kind": "int", "value": value}
    if type(value) is str:
        return {"kind": "str", "value": value}
    if type(value) is bytes:
        return {"kind": "bytes", "hex": value.hex()}
    if type(value) is tuple:
        return {
            "kind": "tuple",
            "items": [_encode_leaf_key_part(item) for item in value],
        }
    raise TypeError(f"unsupported leaf-key part type: {type(value).__qualname__}")


def _decode_leaf_key_part(value: object, *, depth: int) -> object:
    if depth > _MAX_DECODER_DEPTH:
        raise ValueError(
            f"typed-term decoder depth exceeds {_MAX_DECODER_DEPTH} levels"
        )
    data = _require_mapping(value, context="leaf-key component")
    kind = data.get("kind")
    if type(kind) is not str:
        raise ValueError("leaf-key component kind must be a string")

    if kind == "none":
        _require_exact_fields(data, frozenset({"kind"}), context="none component")
        return None
    if kind == "bool":
        _require_exact_fields(
            data, frozenset({"kind", "value"}), context="bool component"
        )
        if type(data["value"]) is not bool:
            raise ValueError("bool component value must be a boolean")
        return data["value"]
    if kind == "int":
        _require_exact_fields(
            data, frozenset({"kind", "value"}), context="int component"
        )
        if type(data["value"]) is not int:
            raise ValueError("int component value must be an integer")
        return data["value"]
    if kind == "str":
        _require_exact_fields(
            data, frozenset({"kind", "value"}), context="str component"
        )
        if type(data["value"]) is not str:
            raise ValueError("str component value must be a string")
        return data["value"]
    if kind == "bytes":
        _require_exact_fields(
            data, frozenset({"kind", "hex"}), context="bytes component"
        )
        encoded = data["hex"]
        if type(encoded) is not str:
            raise ValueError("bytes component hex must be a string")
        try:
            decoded = bytes.fromhex(encoded)
        except ValueError as exc:
            raise ValueError("bytes component hex is malformed") from exc
        if decoded.hex() != encoded:
            raise ValueError("bytes component hex must be canonical lowercase")
        return decoded
    if kind == "tuple":
        _require_exact_fields(
            data, frozenset({"kind", "items"}), context="tuple component"
        )
        items = data["items"]
        if type(items) is not list:
            raise ValueError("tuple component items must be a list")
        return tuple(
            _decode_leaf_key_part(item, depth=depth + 1) for item in items
        )
    raise ValueError(f"unknown leaf-key component kind: {kind}")


def _encode_term(term: TypedBvTerm, active: set[int]) -> dict[str, object]:
    if not isinstance(term, TypedBvTerm):
        raise TypeError("term must be a TypedBvTerm")
    identity = id(term)
    if identity in active:
        raise ValueError("typed-term graph must not contain cycles")
    active.add(identity)
    try:
        leaf_key = (
            None
            if term.leaf_key is None
            else [_encode_leaf_key_part(part) for part in term.leaf_key]
        )
        return {
            "schema_version": TERM_WIRE_SCHEMA_VERSION,
            "operation": term.operation,
            "width": term.width,
            "value": term.value,
            "leaf_key": leaf_key,
            "shift_count": term.shift_count,
            "children": [_encode_term(child, active) for child in term.children],
        }
    finally:
        active.remove(identity)


def typed_term_to_dict(term: TypedBvTerm) -> dict[str, object]:
    """Encode one typed term into the versioned JSON-safe wire shape."""

    return _encode_term(term, set())


def _decode_term(data: object, *, depth: int) -> TypedBvTerm:
    if depth > _MAX_DECODER_DEPTH:
        raise ValueError(
            f"typed-term decoder depth exceeds {_MAX_DECODER_DEPTH} levels"
        )
    payload = _require_mapping(data, context="typed-term")
    _require_exact_fields(payload, _TERM_FIELDS, context="typed-term")

    schema_version = payload["schema_version"]
    if type(schema_version) is not int:
        raise ValueError("schema_version must be an integer")
    if schema_version != TERM_WIRE_SCHEMA_VERSION:
        raise ValueError(f"unknown typed-term schema version: {schema_version}")

    operation = payload["operation"]
    if operation is not None:
        if type(operation) is not str:
            raise ValueError("operation must be a string or None")

    width = payload["width"]
    if type(width) is not int or width <= 0:
        raise ValueError("width must be a positive integer")

    value = payload["value"]
    if value is not None and type(value) is not int:
        raise ValueError("value must be an integer or None")

    raw_leaf_key = payload["leaf_key"]
    if raw_leaf_key is None:
        leaf_key = None
    else:
        if type(raw_leaf_key) is not list:
            raise ValueError("leaf_key must be a list or None")
        leaf_key = tuple(
            _decode_leaf_key_part(part, depth=depth) for part in raw_leaf_key
        )

    shift_count = payload["shift_count"]
    if shift_count is not None and type(shift_count) is not int:
        raise ValueError("shift_count must be an integer or None")

    raw_children = payload["children"]
    if type(raw_children) is not list:
        raise ValueError("children must be a list")
    children = tuple(
        _decode_term(child, depth=depth + 1) for child in raw_children
    )

    try:
        return TypedBvTerm(
            operation=operation,
            width=width,
            value=value,
            leaf_key=leaf_key,
            children=children,
            shift_count=shift_count,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid typed-term wire data: {exc}") from exc


def typed_term_from_dict(data: Mapping[str, object]) -> TypedBvTerm:
    """Decode and validate one versioned typed-term wire object."""

    return _decode_term(data, depth=0)


__all__ = [
    "TERM_WIRE_SCHEMA_VERSION",
    "typed_term_from_dict",
    "typed_term_to_dict",
]
