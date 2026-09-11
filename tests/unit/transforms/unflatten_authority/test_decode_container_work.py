"""Decoder work bounds must not weaken malformed-input publication guards."""

import json
from unittest.mock import patch

import pytest

from d810.transforms.unflatten_authority import bind, ids


def test_nested_sequence_decode_does_not_reencode_each_ancestor_subtree():
    # Reintroducing full subtree comparisons makes this grow quadratically.
    value = "leaf"
    for _ in range(30):
        value = ("sibling", value)
    encoded = ids.canonical_bytes(value)
    original = ids._wire
    visits = 0

    def counted(item):
        nonlocal visits
        visits += 1
        return original(item)

    with patch.object(ids, "_wire", counted):
        decoded = ids.canonical_decode(encoded)

    assert decoded == value
    # 30 tuples plus 31 strings. Permit multiple linear passes, not sum(depth).
    assert visits <= 4 * 61


@pytest.mark.parametrize("outer", ["list", "tuple"])
@pytest.mark.parametrize("nested", [False, True])
def test_decimal_in_sequence_keeps_unsupported_wire_rejection(outer, nested):
    value = {"t": "decimal", "v": "0x1.0000000000000p+0"}
    if nested:
        value = {"t": "tuple", "v": [value]}
    encoded = json.dumps({"t": outer, "v": [value]}, sort_keys=True,
                         separators=(",", ":")).encode("ascii")
    with pytest.raises(TypeError):
        ids.canonical_decode(encoded)
    # Root validation would also reject this, but too late: a parent record
    # must never receive the unsupported float-containing sequence.
    with pytest.raises(TypeError):
        ids._decode_wire(json.loads(encoded))


def test_contextual_index_sentinel_cannot_escape_in_a_sequence():
    wire = {
        "t": "tuple",
        "v": [{"t": "record", "n": "ObligationEvidenceIndex",
               "v": [["cells", {"t": "tuple", "v": []}]]}],
    }
    # A case may consume the sentinel directly, but wrapping it in a sequence
    # must not make it an ordinary canonical value delivered to a parent.
    with pytest.raises(TypeError):
        ids._decode_wire(wire, allow_index=True)


def test_noncanonical_deep_integer_rejects_before_route_publication():
    from d810.analyses.control_flow.semantic_route_evidence import SemanticRouteProofKind
    from .test_bind import _compiler_corridor_unsupported_case

    authority, *_ = _compiler_corridor_unsupported_case(
        proof_kind=SemanticRouteProofKind.STATE_TRANSFORM,
    )
    wire = json.loads(ids.canonical_bytes(authority))
    stack = [wire]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if item.get("t") == "int" and not item["v"].startswith("-"):
                item["v"] = "+" + item["v"]
                break
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    else:
        pytest.fail("fixture lacks a nonnegative integer")

    # Same closed minting capability used by canonical_decode, not a public
    # registry API added for tests. Keep the exception traceback alive so weak
    # publication rows cannot disappear before this assertion observes them.
    mint = next(cell.cell_contents for cell in bind.bind_source_route_authority.__closure__
                if getattr(cell.cell_contents, "__name__", None) == "_route_mint")
    registry = mint.__kwdefaults__["_registry"]
    before = set(registry)
    encoded = json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(ValueError) as failure:
        ids.canonical_decode(encoded)
    assert failure.value is not None
    assert set(registry) - before == set()
