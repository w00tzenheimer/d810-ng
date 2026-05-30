"""Unit tests for portable ``MopSnapshot`` identity helpers (E2a).

Pure-Python tests -- no IDA imports.  These helpers are the
canonical operand-identity functions for dispatcher-state analyses
since E3-rewire; the legacy live-IDA ``_get_mop_key`` /
``_get_mop_offset`` methods they replaced are gone.
"""

from __future__ import annotations

from d810.cfg.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.mop_identity import (
    cfg_operand_slots,
    mop_snapshot_key,
    mop_snapshot_offset,
)


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

    def test_switch_cases_default_empty(self) -> None:
        m = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)

        assert m.switch_cases == ()
        assert m.stack_refs == ()

    def test_switch_cases_preserve_values_and_default_target(self) -> None:
        m = MopSnapshot(
            t=12,
            size=0,
            kind=OperandKind.CASE_LIST,
            switch_cases=(
                ((0, 1), 10),
                ((), 99),
            ),
        )

        assert m.switch_cases == (((0, 1), 10), ((), 99))

    def test_stack_refs_preserve_nested_expression_evidence(self) -> None:
        m = MopSnapshot(
            t=4,
            size=4,
            kind=OperandKind.SUBINSN,
            stack_refs=(0x20, 0x38),
        )

        assert m.stack_refs == (0x20, 0x38)


class TestCfgOperandSlots:
    """``cfg_operand_slots`` is the portable replacement for reading
    ``InsnSnapshot.operand_slots``.  It returns ``(slot, MopSnapshot)``
    pairs sourced from the portable ``l/r/d`` fields and skips
    ``None`` operands.

    Acceptance-rule cover (see ``d810/cfg/mop_identity.py`` docstring):
    portable analyses must read operands via this helper or via
    ``insn.l/r/d`` directly -- never via ``insn.operand_slots`` /
    ``insn.operands`` which today carry the rich Hex-Rays variant.
    """

    def _insn(
        self,
        *,
        l: MopSnapshot | None = None,
        r: MopSnapshot | None = None,
        d: MopSnapshot | None = None,
    ) -> InsnSnapshot:
        """Minimal ``InsnSnapshot`` with only the slot fields set --
        all other required fields get harmless defaults so we can
        exercise the helper without a full lifter run."""
        return InsnSnapshot(
            opcode=1,
            ea=0x140002000,
            operands=(),
            l=l,
            r=r,
            d=d,
            kind=InsnKind.MOV,
        )

    def test_returns_all_three_slots_when_populated(self) -> None:
        left = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        right = MopSnapshot(t=1, size=4, value=42, kind=OperandKind.NUMBER)
        dest = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        insn = self._insn(l=left, r=right, d=dest)

        slots = cfg_operand_slots(insn)

        assert slots == (("l", left), ("r", right), ("d", dest))

    def test_skips_none_operands(self) -> None:
        left = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        dest = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        insn = self._insn(l=left, d=dest)  # r is None

        slots = cfg_operand_slots(insn)

        assert [name for name, _ in slots] == ["l", "d"]

    def test_all_none_returns_empty_tuple(self) -> None:
        insn = self._insn()
        assert cfg_operand_slots(insn) == ()

    def test_slot_order_is_l_r_d(self) -> None:
        """Slot ordering is canonical: left, right, dest.  Callers
        that rely on positional unpacking (e.g. tail.l then tail.r)
        get the same ordering whether they use this helper or the
        raw ``l/r/d`` fields."""
        left = MopSnapshot(t=2, size=4, reg=1, kind=OperandKind.REGISTER)
        right = MopSnapshot(t=2, size=4, reg=2, kind=OperandKind.REGISTER)
        dest = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        insn = self._insn(l=left, r=right, d=dest)

        slots = cfg_operand_slots(insn)

        assert tuple(name for name, _ in slots) == ("l", "r", "d")

    def test_return_type_is_portable_mopsnapshot(self) -> None:
        """The whole point of this helper: callers see a portable
        ``MopSnapshot``, not the rich Hex-Rays variant that
        ``insn.operand_slots`` could carry."""
        left = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        insn = self._insn(l=left)

        ((_, operand),) = cfg_operand_slots(insn)

        assert isinstance(operand, MopSnapshot)
        # Operand is suitable for direct ID-helper consumption -- this
        # is the architectural contract: portable in, portable out.
        assert mop_snapshot_key(operand) == "r3"
        assert mop_snapshot_offset(operand) == 3
