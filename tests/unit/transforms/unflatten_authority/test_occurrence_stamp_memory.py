"""The phase-local cache guard must cost constant memory (ticket d81-aw7v).

``_occurrence_stamp`` used to return a full recursive *tuple mirror* of the
value it guarded. Two costs followed:

* the mirror is alive as a local in ``canonical_bytes`` while ``_wire`` and
  ``json.dumps`` build their own copies, so peak memory at the serialization
  frame carried one extra deep copy of the whole value;
* ``CanonicalValidationSession`` retains one mirror per cached occurrence, and
  records nest, so the retained total grows as O(nodes x depth).

Measured on a nested mapping before the fix: the mirror is ~2.3x the deep size
of the value it mirrors, and retaining one mirror per node reached 12.6x /
17.1x / 21.7x the whole value's size at depths 5 / 7 / 9. On Target A
(``sub_7FF8569F0540``) that exhausted the heap and ``json.dumps`` raised
``MemoryError`` inside ``canonical_bytes``, which the transaction reported as
``disposition=rejected_preflight reason=runtime:preflight``.

A stamp only has to answer "is this exact object still byte-identical to when
it was cached", so a fixed-size digest is sufficient and bounded.
"""

from __future__ import annotations

import sys
from types import MappingProxyType

import pytest

from d810.transforms.unflatten_authority.ids import _occurrence_stamp


def _deep_size(obj: object, seen: set[int] | None = None) -> int:
    seen = set() if seen is None else seen
    if id(obj) in seen:
        return 0
    seen.add(id(obj))
    total = sys.getsizeof(obj)
    if isinstance(obj, dict):
        for key, value in obj.items():
            total += _deep_size(key, seen) + _deep_size(value, seen)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            total += _deep_size(item, seen)
    return total


def _tree(depth: int, width: int) -> dict[str, object]:
    if depth == 0:
        return {"ref": "blk[123]@0x18001e83b", "ea": 0x180012EA0, "kind": "route"}
    return {"n": depth, "kids": tuple(_tree(depth - 1, width) for _ in range(width))}


def _mappings(value: object):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _mappings(item)
    elif isinstance(value, tuple):
        for item in value:
            yield from _mappings(item)


def test_stamp_size_does_not_grow_with_the_value_it_guards() -> None:
    small = _tree(1, 2)
    large = _tree(8, 3)

    assert _deep_size(large) > 50 * _deep_size(small)
    assert _deep_size(_occurrence_stamp(large)) == _deep_size(_occurrence_stamp(small))


def test_retaining_one_stamp_per_nested_record_stays_bounded() -> None:
    # One stamp per nested record is exactly what ``_record_content_id``
    # retains in the session cache for a single preparation phase.
    value = _tree(7, 3)
    nodes = list(_mappings(value))
    assert len(nodes) > 3000

    retained = [_occurrence_stamp(node) for node in nodes]
    seen: set[int] = set()
    total = sum(_deep_size(stamp, seen) for stamp in retained)

    # The deep tuple mirror reached 17x the value's own size here.
    assert total < _deep_size(value)


def test_stamp_detects_a_mutated_nested_field() -> None:
    value = _tree(3, 2)
    before = _occurrence_stamp(value)

    leaf = next(node for node in _mappings(value) if "ref" in node)
    leaf["ref"] = "blk[124]@0x18001e83b"

    assert _occurrence_stamp(value) != before


def test_stamp_is_stable_for_an_unmutated_value() -> None:
    value = _tree(4, 3)

    assert _occurrence_stamp(value) == _occurrence_stamp(value)


def test_equal_content_in_distinct_objects_stamps_equal() -> None:
    assert _occurrence_stamp(_tree(3, 2)) == _occurrence_stamp(_tree(3, 2))


@pytest.mark.parametrize(
    "left,right",
    [
        (True, 1),
        (False, 0),
        ((1, 2), [1, 2]),
        ({"a": 1}, MappingProxyType({"a": 1})),
        ("1", 1),
        (b"1", "1"),
        (1.0, 1),
        ((1, (2,)), ((1,), 2)),
    ],
)
def test_stamp_separates_values_the_tuple_mirror_separated(
    left: object, right: object
) -> None:
    assert _occurrence_stamp(left) != _occurrence_stamp(right)


def test_stamp_terminates_on_a_self_referential_container() -> None:
    value: dict[str, object] = {"self": None}
    value["self"] = value

    assert _occurrence_stamp(value) == _occurrence_stamp(value)


def test_stamp_of_a_deep_value_does_not_exhaust_the_interpreter_stack() -> None:
    # ``_tree(60, 1)`` nests ~120 containers; the guard must survive the same
    # nesting depth the authority records reach.
    value = _tree(60, 1)

    assert isinstance(_occurrence_stamp(value), bytes)
