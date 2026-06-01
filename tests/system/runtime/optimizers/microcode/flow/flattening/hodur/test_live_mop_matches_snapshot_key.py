"""Behavior tests for ``_live_mop_matches_snapshot_key`` (E3-schema P2).

The function lives in
``d810.backends.hexrays.evidence.analysis`` which
imports ``ida_hexrays`` -- can't run from ``tests/unit/`` per the
``unit-tests-no-hexrays`` contract.  Lives here in
``tests/system/runtime/hodur/`` and exercises the matcher with
stubbed ``mop_t``-shaped objects so the cases run without a live
decompilation.

The companion source-string assertion in
``tests/unit/recon/flow/test_live_mop_matches_snapshot_key.py``
covers the key-formula text mirror.  This file covers the
*behavior*: cached portable identity actually matches the live
operand of the same kind, and DOES NOT match cross-kind operands
even at the same numeric value.
"""

from __future__ import annotations

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from types import SimpleNamespace

from d810.ir.flowgraph import MopSnapshot, OperandKind
from d810.ir.mop_identity import mop_snapshot_key
from d810.backends.hexrays.evidence.analysis import (
    _live_mop_matches_snapshot_key,
)


def _stub_stack_mop(off: int) -> SimpleNamespace:
    """``mop_t``-shaped stub for an ``mop_S`` stack operand.

    The matcher reads ``mop.t`` and ``mop.s.off`` for STACK; we
    provide both via ``SimpleNamespace``."""
    return SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=off))


def _stub_register_mop(reg: int) -> SimpleNamespace:
    return SimpleNamespace(t=ida_hexrays.mop_r, r=reg)


def _stub_global_mop(gaddr: int) -> SimpleNamespace:
    return SimpleNamespace(t=ida_hexrays.mop_v, g=gaddr)


def _stub_lvar_mop(off: int) -> SimpleNamespace:
    return SimpleNamespace(t=ida_hexrays.mop_l, l=SimpleNamespace(off=off))


class TestCrossKindMatching:
    """Cached portable identity matches the live operand of the
    same kind at the same numeric value -- and ONLY that operand."""

    def test_stack_cache_matches_stack_live(self) -> None:
        cached = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        live = _stub_stack_mop(off=0x40)
        assert _live_mop_matches_snapshot_key(live, mop_snapshot_key(cached))

    def test_register_cache_matches_register_live(self) -> None:
        cached = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        live = _stub_register_mop(reg=3)
        assert _live_mop_matches_snapshot_key(live, mop_snapshot_key(cached))

    def test_global_cache_matches_global_live(self) -> None:
        cached = MopSnapshot(
            t=8, size=8, gaddr=0x140002000, kind=OperandKind.GLOBAL
        )
        live = _stub_global_mop(gaddr=0x140002000)
        assert _live_mop_matches_snapshot_key(live, mop_snapshot_key(cached))

    def test_lvar_cache_matches_lvar_live(self) -> None:
        cached = MopSnapshot(t=9, size=4, lvar_off=8, kind=OperandKind.LVAR)
        live = _stub_lvar_mop(off=8)
        assert _live_mop_matches_snapshot_key(live, mop_snapshot_key(cached))


class TestCrossKindRejection:
    """The prefix scheme in the key formula prevents a STACK operand
    at offset 3 from matching a REGISTER operand at reg=3.  These
    tests pin that the kind tag is load-bearing -- a future edit
    that drops the prefix (e.g. returns ``str(mop.r)`` instead of
    ``f"r{mop.r}"``) would let cross-kind operands match.
    """

    def test_register_key_does_not_match_stack_live_at_same_value(
        self,
    ) -> None:
        cached_reg = MopSnapshot(
            t=2, size=4, reg=3, kind=OperandKind.REGISTER
        )
        live_stack = _stub_stack_mop(off=3)
        assert not _live_mop_matches_snapshot_key(
            live_stack, mop_snapshot_key(cached_reg)
        )

    def test_stack_key_does_not_match_register_live_at_same_value(
        self,
    ) -> None:
        cached_stack = MopSnapshot(
            t=4, size=4, stkoff=3, kind=OperandKind.STACK
        )
        live_reg = _stub_register_mop(reg=3)
        assert not _live_mop_matches_snapshot_key(
            live_reg, mop_snapshot_key(cached_stack)
        )

    def test_global_key_does_not_match_lvar_live_at_same_value(self) -> None:
        cached_global = MopSnapshot(
            t=8, size=8, gaddr=8, kind=OperandKind.GLOBAL
        )
        live_lvar = _stub_lvar_mop(off=8)
        assert not _live_mop_matches_snapshot_key(
            live_lvar, mop_snapshot_key(cached_global)
        )


class TestDifferentValueRejection:
    """Same kind but different numeric value must NOT match."""

    def test_stack_different_offset_rejected(self) -> None:
        cached = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        live = _stub_stack_mop(off=0x80)
        assert not _live_mop_matches_snapshot_key(
            live, mop_snapshot_key(cached)
        )

    def test_register_different_reg_rejected(self) -> None:
        cached = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        live = _stub_register_mop(reg=7)
        assert not _live_mop_matches_snapshot_key(
            live, mop_snapshot_key(cached)
        )


class TestUnsupportedAndDegenerate:
    """``None`` inputs and unsupported snapshot kinds don't match.
    The matcher MUST NOT raise on these cases -- it's called inside
    a loop over potentially-noisy state check blocks."""

    def test_none_key_returns_false(self) -> None:
        """``mop_snapshot_key`` returns ``None`` for non-keyable
        snapshots (NUMBER, UNKNOWN, etc.).  The matcher accepts
        the ``None`` key and returns ``False`` rather than
        raising."""
        live = _stub_stack_mop(off=0x40)
        assert not _live_mop_matches_snapshot_key(live, None)

    def test_none_mop_returns_false(self) -> None:
        """A live mop that's ``None`` (defensive guard) returns
        ``False`` cleanly."""
        assert not _live_mop_matches_snapshot_key(None, "S64")

    def test_number_cache_returns_false(self) -> None:
        """A cached snapshot of an ``mop_n`` (NUMBER) can't produce
        a key -- the cache should never put one here, but if it
        did the matcher returns ``False``."""
        cached_num = MopSnapshot(t=1, size=4, value=42, kind=OperandKind.NUMBER)
        cached_key = mop_snapshot_key(cached_num)
        assert cached_key is None
        # And any live mop against this None key is also False.
        live = _stub_stack_mop(off=42)
        assert not _live_mop_matches_snapshot_key(live, cached_key)

    def test_unsupported_live_kind_returns_false(self) -> None:
        """A live operand with an unsupported ``mop.t`` (e.g.
        ``mop_n`` / ``mop_b`` / ``mop_d``) doesn't match any
        STACK/REGISTER/GLOBAL/LVAR cached key."""
        live_num = SimpleNamespace(t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=42))
        assert not _live_mop_matches_snapshot_key(live_num, "S42")
        assert not _live_mop_matches_snapshot_key(live_num, "r42")
        assert not _live_mop_matches_snapshot_key(live_num, "v42")
        assert not _live_mop_matches_snapshot_key(live_num, "l42")
