"""Tests for the versioned, JSON-safe typed-term codec."""

from __future__ import annotations

import json

import pytest

from d810.mba.term_codec import (
    TERM_WIRE_SCHEMA_VERSION,
    typed_term_from_dict,
    typed_term_to_dict,
)
from d810.mba.typed_term import (
    TypedBvTerm,
    fixed_shift_term,
    term_fingerprint,
)


def _leaf(width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("register", "x"))


def _constant(value: int, width: int) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def _binary(operation: str, left: TypedBvTerm, right: TypedBvTerm) -> TypedBvTerm:
    return TypedBvTerm(operation, left.width, children=(left, right))


@pytest.mark.parametrize("width", (8, 16, 32, 64))
def test_constants_round_trip_with_fixed_width_mask_normalization(width: int) -> None:
    term = _constant((1 << width) + 5, width)

    encoded = typed_term_to_dict(term)
    decoded = typed_term_from_dict(encoded)

    assert encoded["schema_version"] == TERM_WIRE_SCHEMA_VERSION
    assert encoded["value"] == 5
    assert decoded == term
    assert term_fingerprint(decoded) == term_fingerprint(term)


def test_nested_leaf_key_components_round_trip_with_explicit_tags() -> None:
    leaf = TypedBvTerm(
        None,
        32,
        leaf_key=(
            None,
            False,
            True,
            -3,
            "text",
            b"\x00\xff",
            ("nested", False, (1, b"x")),
        ),
    )

    decoded = typed_term_from_dict(typed_term_to_dict(leaf))

    assert decoded == leaf
    assert term_fingerprint(decoded) == term_fingerprint(leaf)
    assert typed_term_to_dict(leaf)["leaf_key"] == [
        {"kind": "none"},
        {"kind": "bool", "value": False},
        {"kind": "bool", "value": True},
        {"kind": "int", "value": -3},
        {"kind": "str", "value": "text"},
        {"kind": "bytes", "hex": "00ff"},
        {
            "kind": "tuple",
            "items": [
                {"kind": "str", "value": "nested"},
                {"kind": "bool", "value": False},
                {
                    "kind": "tuple",
                    "items": [
                        {"kind": "int", "value": 1},
                        {"kind": "bytes", "hex": "78"},
                    ],
                },
            ],
        },
    ]


@pytest.mark.parametrize(
    "term",
    (
        TypedBvTerm("bnot", 32, children=(_leaf(),)),
        _binary("xor", _leaf(), _constant(7, 32)),
        fixed_shift_term("shl", 32, _leaf(), 3),
        fixed_shift_term("rol", 32, _leaf(), 11),
        TypedBvTerm(
            "sub",
            32,
            children=(
                _binary("and", _leaf(), _constant(0xFF, 32)),
                fixed_shift_term("ror", 32, _leaf(), 5),
            ),
        ),
    ),
)
def test_all_term_shapes_round_trip_and_preserve_fingerprint(
    term: TypedBvTerm,
) -> None:
    decoded = typed_term_from_dict(typed_term_to_dict(term))

    assert decoded == term
    assert term_fingerprint(decoded) == term_fingerprint(term)


def test_wire_dictionary_is_deterministic_and_has_fixed_key_order() -> None:
    term = fixed_shift_term("ror", 16, _leaf(16), 7)

    first = typed_term_to_dict(term)
    second = typed_term_to_dict(term)

    assert first == second
    assert list(first) == [
        "schema_version",
        "operation",
        "width",
        "value",
        "leaf_key",
        "shift_count",
        "children",
    ]
    assert json.dumps(first, ensure_ascii=True, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=True, separators=(",", ":")
    )


def _valid_payload() -> dict[str, object]:
    return typed_term_to_dict(_binary("xor", _leaf(), _constant(1, 32)))


@pytest.mark.parametrize(
    "mutate",
    (
        lambda data: data.update(schema_version=2),
        lambda data: data.pop("children"),
        lambda data: data.update(extra=True),
        lambda data: data.update(operation="unknown"),
        lambda data: data.update(children=data["children"][:1]),
        lambda data: data["children"].__setitem__(
            1, typed_term_to_dict(_constant(1, 16))
        ),
        lambda data: data.update(value=1, leaf_key=[{"kind": "str", "value": "x"}]),
        lambda data: data.update(leaf_key=[b"untagged"]),
        lambda data: data.update(
            leaf_key=[{"kind": "tuple", "items": ("not", "a", "list")}]
        ),
        lambda data: data.update(width=True),
        lambda data: data.update(value=True),
        lambda data: data.update(shift_count=True),
    ),
)
def test_malformed_wire_data_is_rejected(mutate) -> None:
    payload = _valid_payload()
    mutate(payload)

    with pytest.raises((TypeError, ValueError)):
        typed_term_from_dict(payload)


def test_recursive_decoder_limit_rejects_depth_over_256() -> None:
    payload: dict[str, object] = {
        "schema_version": 1,
        "operation": None,
        "width": 8,
        "value": 0,
        "leaf_key": None,
        "shift_count": None,
        "children": [],
    }
    for _ in range(257):
        payload = {
            "schema_version": 1,
            "operation": "bnot",
            "width": 8,
            "value": None,
            "leaf_key": None,
            "shift_count": None,
            "children": [payload],
        }

    with pytest.raises(ValueError, match="depth"):
        typed_term_from_dict(payload)


def _nested_tuple_component(depth: int) -> list[dict[str, object]]:
    component: dict[str, object] = {"kind": "str", "value": "leaf"}
    for _ in range(depth):
        component = {"kind": "tuple", "items": [component]}
    return [component]


def _leaf_payload_with_nested_tuple(depth: int) -> dict[str, object]:
    payload = typed_term_to_dict(TypedBvTerm(None, 8, value=0))
    payload["leaf_key"] = _nested_tuple_component(depth)
    payload["value"] = None
    return payload


@pytest.mark.parametrize("depth", (255, 256))
def test_leaf_key_tuple_nesting_at_or_below_decoder_limit_is_accepted(
    depth: int,
) -> None:
    decoded = typed_term_from_dict(_leaf_payload_with_nested_tuple(depth))

    assert decoded.width == 8
    assert decoded.leaf_key is not None


@pytest.mark.parametrize("depth", (257, 1000))
def test_leaf_key_tuple_nesting_over_decoder_limit_is_rejected_as_codec_error(
    depth: int,
) -> None:
    with pytest.raises(ValueError, match="depth"):
        typed_term_from_dict(_leaf_payload_with_nested_tuple(depth))


def test_decoder_delegates_operation_vocabulary_and_arity_to_typed_term(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import d810.mba.typed_term as typed_term_module

    future_operation = "future_binary"
    monkeypatch.setattr(
        typed_term_module,
        "SUPPORTED_OPERATIONS",
        typed_term_module.SUPPORTED_OPERATIONS | {future_operation},
    )
    payload = _valid_payload()
    payload["operation"] = future_operation

    decoded = typed_term_from_dict(payload)

    assert decoded.operation == future_operation
    assert len(decoded.children) == 2


def test_extension_api_re_exports_codec_without_ida_imports() -> None:
    import sys

    from d810.mba import extension_api

    assert extension_api.typed_term_to_dict is typed_term_to_dict
    assert extension_api.typed_term_from_dict is typed_term_from_dict
    assert "typed_term_to_dict" in extension_api.__all__
    assert "typed_term_from_dict" in extension_api.__all__
    assert "idaapi" not in sys.modules
    assert "ida_hexrays" not in sys.modules
