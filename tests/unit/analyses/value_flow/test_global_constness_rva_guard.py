"""rva_guard: how the pointer-like veto is answered (lpccp-suvl).

The legacy veto asks "does this VALUE resemble an address?" -- a value-shape
guess. ``rva_guard`` lets a caller answer the real question instead: does the
loaded value actually reach a dereference?

    rva_guard=False -> no veto at all; fold whenever the policy otherwise allows
    rva_guard=True  -> veto only when the value is proven to reach a dereference;
                       when the def-use answer is unavailable, fall back to the
                       value-shape test so behavior is unchanged.
"""

from __future__ import annotations

import pytest

from d810.analyses.value_flow.global_constness import (
    GlobalConstEvidence,
    GlobalConstPolicy,
    GlobalConstReason,
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
        "item_kind": __import__(
            "d810.analyses.value_flow.global_constness",
            fromlist=["GlobalItemKind"],
        ).GlobalItemKind.DATA,
        "has_direct_write": False,
        "reaching_write": False,
        "initializer_stable_at_read": False,
        "value": 0x2606EC5,
        "value_is_pointer_like": True,
    }
    values.update(changes)
    return GlobalConstEvidence(**values)


# --------------------------------------------------------------------------- #
# default behavior is unchanged                                               #
# --------------------------------------------------------------------------- #


def test_default_keeps_value_shape_veto():
    """No rva_guard argument, no def-use answer -> today's behavior exactly."""
    decision = decide_global_const_read(_evidence(), GlobalConstPolicy.STRICT)
    assert decision.can_inline_read is False
    assert decision.reason is GlobalConstReason.POINTER_LIKE_VALUE


def test_guard_true_without_defuse_answer_falls_back_to_value_shape():
    """rva_guard=True but the trace could not run -> stay conservative."""
    decision = decide_global_const_read(
        _evidence(value_reaches_dereference=None),
        GlobalConstPolicy.STRICT,
        rva_guard=True,
    )
    assert decision.can_inline_read is False
    assert decision.reason is GlobalConstReason.POINTER_LIKE_VALUE


# --------------------------------------------------------------------------- #
# rva_guard=True: def-use answer replaces the guess                           #
# --------------------------------------------------------------------------- #


def test_guard_true_folds_when_defuse_proves_data_only():
    """The lpccp-p1n2 case: pointer-shaped value used only in arithmetic."""
    decision = decide_global_const_read(
        _evidence(value_reaches_dereference=False),
        GlobalConstPolicy.STRICT,
        rva_guard=True,
    )
    assert decision.can_inline_read is True
    assert decision.value == 0x2606EC5
    assert decision.reason is GlobalConstReason.READONLY_DATA


def test_guard_true_vetoes_when_defuse_proves_dereference():
    decision = decide_global_const_read(
        _evidence(value_reaches_dereference=True),
        GlobalConstPolicy.STRICT,
        rva_guard=True,
    )
    assert decision.can_inline_read is False
    assert decision.reason is GlobalConstReason.VALUE_REACHES_DEREFERENCE


def test_defuse_veto_is_distinguishable_from_value_shape_veto():
    """The two vetoes must not share a reason -- they are different evidence."""
    assert (
        GlobalConstReason.VALUE_REACHES_DEREFERENCE
        is not GlobalConstReason.POINTER_LIKE_VALUE
    )


# --------------------------------------------------------------------------- #
# rva_guard=False: no veto                                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("reaches", [None, False, True])
def test_guard_false_never_vetoes_on_pointer_shape(reaches):
    decision = decide_global_const_read(
        _evidence(value_reaches_dereference=reaches),
        GlobalConstPolicy.STRICT,
        rva_guard=False,
    )
    assert decision.can_inline_read is True
    assert decision.value == 0x2606EC5


# --------------------------------------------------------------------------- #
# the guard must not reach beyond the pointer veto                            #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("rva_guard", [True, False])
def test_guard_cannot_resurrect_a_read_rejected_for_another_reason(rva_guard):
    """Writable memory under STRICT stays rejected whatever rva_guard says."""
    decision = decide_global_const_read(
        _evidence(writable=True, value_reaches_dereference=False),
        GlobalConstPolicy.STRICT,
        rva_guard=rva_guard,
    )
    assert decision.can_inline_read is False
    assert decision.reason is GlobalConstReason.WRITABLE_MEMORY


@pytest.mark.parametrize("rva_guard", [True, False])
def test_guard_does_not_change_non_pointer_like_reads(rva_guard):
    decision = decide_global_const_read(
        _evidence(value_is_pointer_like=False, value=0xCD75E00B),
        GlobalConstPolicy.STRICT,
        rva_guard=rva_guard,
    )
    assert decision.can_inline_read is True
    assert decision.value == 0xCD75E00B


def test_guard_false_does_not_authorize_persistent_const_for_pointer_values():
    """Folding one read is ephemeral; persistence is a separate authority."""
    decision = decide_global_const_read(
        _evidence(), GlobalConstPolicy.STRICT, rva_guard=False
    )
    assert decision.can_inline_read is True
    assert decision.can_persist_const is True  # readonly data item, as before


def test_aggressive_policy_still_folds_writable_under_guard():
    """rva_guard is orthogonal to the writable-memory policy (lpccp-pwwf)."""
    decision = decide_global_const_read(
        _evidence(
            writable=True,
            value_is_pointer_like=False,
            value_reaches_dereference=False,
        ),
        GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES,
        rva_guard=True,
    )
    assert decision.can_inline_read is True
    assert decision.reason is GlobalConstReason.AGGRESSIVE_NO_DIRECT_WRITES
