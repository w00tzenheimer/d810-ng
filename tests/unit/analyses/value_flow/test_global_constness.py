from __future__ import annotations

import pytest

from d810.analyses.value_flow.global_constness import (
    GlobalConstEvidence,
    GlobalConstPolicy,
    GlobalConstReason,
    GlobalItemKind,
    decide_global_const_read,
)


def _evidence(**changes: object) -> GlobalConstEvidence:
    values: dict[str, object] = {
        "address": 0x1004,
        "item_head": 0x1000,
        "item_end": 0x1010,
        "read_size": 4,
        "readable": True,
        "writable": False,
        "executable": False,
        "item_kind": GlobalItemKind.DATA,
        "has_direct_write": False,
        "reaching_write": False,
        "initializer_stable_at_read": False,
        "value": 0x12345678,
    }
    values.update(changes)
    return GlobalConstEvidence(**values)


@pytest.mark.parametrize(
    ("evidence", "policy", "dangerous", "inline", "persist", "reason"),
    [
        (
            _evidence(),
            GlobalConstPolicy.STRICT,
            False,
            True,
            True,
            GlobalConstReason.READONLY_DATA,
        ),
        (
            _evidence(executable=True),
            GlobalConstPolicy.STRICT,
            False,
            True,
            True,
            GlobalConstReason.READONLY_DATA,
        ),
        (
            _evidence(executable=True, item_kind=GlobalItemKind.CODE),
            GlobalConstPolicy.STRICT,
            False,
            False,
            False,
            GlobalConstReason.EXECUTABLE_ITEM_REJECTED,
        ),
        (
            _evidence(executable=True, item_kind=GlobalItemKind.UNKNOWN),
            GlobalConstPolicy.STRICT,
            True,
            True,
            False,
            GlobalConstReason.DANGEROUS_EXECUTABLE_READONLY_OVERRIDE,
        ),
        (
            _evidence(writable=True),
            GlobalConstPolicy.STRICT,
            False,
            False,
            False,
            GlobalConstReason.WRITABLE_MEMORY,
        ),
        (
            _evidence(writable=True),
            GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES,
            False,
            True,
            False,
            GlobalConstReason.AGGRESSIVE_NO_DIRECT_WRITES,
        ),
        (
            _evidence(writable=True, has_direct_write=True),
            GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES,
            False,
            False,
            False,
            GlobalConstReason.DIRECT_WRITE_WITHOUT_STABLE_READ,
        ),
        (
            _evidence(
                writable=True,
                has_direct_write=True,
                initializer_stable_at_read=True,
            ),
            GlobalConstPolicy.STRICT,
            False,
            True,
            False,
            GlobalConstReason.INITIALIZER_STABLE_AT_READ,
        ),
        (
            _evidence(reaching_write=True, initializer_stable_at_read=True),
            GlobalConstPolicy.STRICT,
            False,
            False,
            False,
            GlobalConstReason.REACHING_WRITE,
        ),
        (
            _evidence(readable=False),
            GlobalConstPolicy.STRICT,
            False,
            False,
            False,
            GlobalConstReason.NOT_READABLE,
        ),
        (
            _evidence(value=None),
            GlobalConstPolicy.STRICT,
            False,
            False,
            False,
            GlobalConstReason.VALUE_UNAVAILABLE,
        ),
        (
            _evidence(read_size=3),
            GlobalConstPolicy.STRICT,
            False,
            False,
            False,
            GlobalConstReason.UNSUPPORTED_WIDTH,
        ),
        (
            _evidence(address=0x100E),
            GlobalConstPolicy.STRICT,
            False,
            False,
            False,
            GlobalConstReason.READ_OUT_OF_BOUNDS,
        ),
    ],
)
def test_global_constness_decision_table(
    evidence: GlobalConstEvidence,
    policy: GlobalConstPolicy,
    dangerous: bool,
    inline: bool,
    persist: bool,
    reason: GlobalConstReason,
) -> None:
    decision = decide_global_const_read(
        evidence,
        policy,
        allow_executable_readonly=dangerous,
    )

    assert decision.can_inline_read is inline
    assert decision.can_persist_const is persist
    assert decision.reason is reason
    assert decision.value == (evidence.value if inline else None)
    assert decision.used_dangerous_override is (
        reason is GlobalConstReason.DANGEROUS_EXECUTABLE_READONLY_OVERRIDE
    )


def test_dangerous_override_cannot_bypass_writable_memory() -> None:
    decision = decide_global_const_read(
        _evidence(
            writable=True,
            executable=True,
            item_kind=GlobalItemKind.CODE,
        ),
        GlobalConstPolicy.STRICT,
        allow_executable_readonly=True,
    )

    assert decision.can_inline_read is False
    assert decision.reason is GlobalConstReason.WRITABLE_MEMORY


def test_dangerous_override_cannot_bypass_reaching_write() -> None:
    decision = decide_global_const_read(
        _evidence(
            executable=True,
            item_kind=GlobalItemKind.CODE,
            reaching_write=True,
        ),
        GlobalConstPolicy.STRICT,
        allow_executable_readonly=True,
    )

    assert decision.can_inline_read is False
    assert decision.reason is GlobalConstReason.REACHING_WRITE


def test_non_executable_unknown_item_is_not_force_folded() -> None:
    decision = decide_global_const_read(
        _evidence(item_kind=GlobalItemKind.UNKNOWN),
        GlobalConstPolicy.STRICT,
        allow_executable_readonly=True,
    )

    assert decision.can_inline_read is False
    assert decision.reason is GlobalConstReason.UNSUPPORTED_ITEM_KIND
