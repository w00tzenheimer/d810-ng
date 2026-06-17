from __future__ import annotations

from types import SimpleNamespace

from d810.transforms.state_var_cleanup import (
    collect_state_constants,
    is_known_state_constant,
)


def test_collect_state_constants_merges_snapshot_and_dispatcher_maps() -> None:
    range_evidence = SimpleNamespace(
        handler_state_map={10: 0x1000, 20: 0x2000},
        handler_range_map={30: (0x3000, 0x30FF), 40: (None, 0x40FF)},
    )

    constants = collect_state_constants((0xABCD,), range_evidence)

    assert constants == frozenset({0xABCD, 0x1000, 0x2000, 0x3000, 0x30FF, 0x40FF})


def test_collect_state_constants_handles_missing_range_evidence() -> None:
    assert collect_state_constants((1, 2), None) == frozenset({1, 2})


def test_is_known_state_constant_supports_optional_32_bit_masking() -> None:
    assert is_known_state_constant(0x1_0000_1234, {0x1234}, mask32=True)
    assert not is_known_state_constant(0x1_0000_1234, {0x1234}, mask32=False)
