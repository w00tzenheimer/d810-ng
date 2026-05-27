"""Unit tests for portable ``MopSnapshot`` identity helpers (E2a).

Pure-Python tests -- no IDA imports.  Covers parity with the live-IDA
``DispatcherCache._get_mop_key`` / ``DispatcherCache._get_mop_offset``
helpers in ``d810.recon.flow.dispatcher_detection``.
"""

from __future__ import annotations

from d810.cfg.flowgraph import MopSnapshot, OperandKind
from d810.cfg.mop_identity import mop_snapshot_key, mop_snapshot_offset


class TestMopSnapshotKey:
    """``mop_snapshot_key`` returns prefixed strings keyed by operand kind.

    Prefix scheme matches the live-IDA original so future swap-in is
    string-identical (``"r3"``, ``"S40"``, ``"v0x140002000"``, ``"l8"``).
    """

    def test_register_key(self) -> None:
        m = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        assert mop_snapshot_key(m) == "r3"

    def test_stack_key(self) -> None:
        m = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        assert mop_snapshot_key(m) == "S64"

    def test_global_key(self) -> None:
        m = MopSnapshot(t=8, size=8, gaddr=0x140002000, kind=OperandKind.GLOBAL)
        assert mop_snapshot_key(m) == "v5368717312"

    def test_lvar_key(self) -> None:
        m = MopSnapshot(t=9, size=4, lvar_off=8, kind=OperandKind.LVAR)
        assert mop_snapshot_key(m) == "l8"

    def test_number_returns_none(self) -> None:
        """Numbers don't carry a portable identity -- the legacy helper
        also returned ``None`` for ``mop_n``.  Keyed values would
        collide with other kinds at the same numeric value."""
        m = MopSnapshot(t=1, size=4, value=42, kind=OperandKind.NUMBER)
        assert mop_snapshot_key(m) is None

    def test_unknown_returns_none(self) -> None:
        m = MopSnapshot(t=0, size=0, kind=OperandKind.UNKNOWN)
        assert mop_snapshot_key(m) is None

    def test_none_input_returns_none(self) -> None:
        """The helper is safe to call on ``None`` (matches the legacy
        helper, which crashed on ``None`` -- we improve here)."""
        assert mop_snapshot_key(None) is None

    def test_register_missing_field_returns_none(self) -> None:
        """If the kind says REGISTER but ``reg`` was never populated,
        the helper returns ``None`` rather than fabricating a key."""
        m = MopSnapshot(t=2, size=4, kind=OperandKind.REGISTER)
        assert mop_snapshot_key(m) is None

    def test_stack_and_register_distinct_at_same_value(self) -> None:
        """The prefix scheme prevents ``r3`` colliding with ``S3``.
        This is the actual reason the legacy helper used prefixed
        strings instead of raw ints."""
        r = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        s = MopSnapshot(t=4, size=4, stkoff=3, kind=OperandKind.STACK)
        assert mop_snapshot_key(r) != mop_snapshot_key(s)


class TestMopSnapshotOffset:
    """``mop_snapshot_offset`` returns the per-kind numeric identifier.

    Parity with the live-IDA ``_get_mop_offset`` that returns ``0``
    for unsupported kinds.
    """

    def test_register_offset_is_reg_number(self) -> None:
        m = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        assert mop_snapshot_offset(m) == 3

    def test_stack_offset_is_stkoff(self) -> None:
        m = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        assert mop_snapshot_offset(m) == 0x40

    def test_global_offset_is_gaddr(self) -> None:
        m = MopSnapshot(t=8, size=8, gaddr=0x140002000, kind=OperandKind.GLOBAL)
        assert mop_snapshot_offset(m) == 0x140002000

    def test_lvar_offset_is_lvar_off(self) -> None:
        m = MopSnapshot(t=9, size=4, lvar_off=8, kind=OperandKind.LVAR)
        assert mop_snapshot_offset(m) == 8

    def test_number_falls_back_to_zero(self) -> None:
        """Legacy ``_get_mop_offset`` returned ``0`` for ``mop_n``."""
        m = MopSnapshot(t=1, size=4, value=42, kind=OperandKind.NUMBER)
        assert mop_snapshot_offset(m) == 0

    def test_unknown_falls_back_to_zero(self) -> None:
        m = MopSnapshot(t=0, size=0, kind=OperandKind.UNKNOWN)
        assert mop_snapshot_offset(m) == 0

    def test_none_input_falls_back_to_zero(self) -> None:
        assert mop_snapshot_offset(None) == 0

    def test_register_missing_field_falls_back_to_zero(self) -> None:
        """Kind tag without the identity field -- helper falls back."""
        m = MopSnapshot(t=2, size=4, kind=OperandKind.REGISTER)
        assert mop_snapshot_offset(m) == 0


class TestMopSnapshotFieldsBackwardsCompatible:
    """E2a added two optional fields to ``MopSnapshot``.  Existing
    consumers that construct snapshots without the new fields must
    continue to work unchanged."""

    def test_construct_without_new_fields(self) -> None:
        """Pre-E2a construction pattern -- no ``gaddr``, no ``lvar_off``."""
        m = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        assert m.gaddr is None
        assert m.lvar_off is None

    def test_construct_with_new_fields(self) -> None:
        m = MopSnapshot(
            t=8,
            size=8,
            gaddr=0x140002000,
            kind=OperandKind.GLOBAL,
        )
        assert m.gaddr == 0x140002000
        assert m.lvar_off is None
