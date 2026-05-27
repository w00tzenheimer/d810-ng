"""Unit cover for ``InsnKind.TABLE_JUMP`` (E3-prep).

Pure-Python -- the ``InsnKind`` enum lives in ``d810.cfg.flowgraph``
and has no IDA imports.  The lifter mapping
(``m_jtbl`` -> ``InsnKind.TABLE_JUMP``) is covered separately in
``tests/system/runtime/hexrays/test_ir_translator.py`` because the
lifter imports ``ida_hexrays``.
"""

from __future__ import annotations

from d810.cfg.flowgraph import InsnKind


class TestTableJumpKind:
    """``TABLE_JUMP`` is the portable kind for multi-target jump-table
    tails (Hex-Rays ``m_jtbl`` today; future backends may use this
    for switch-style indirect jumps too)."""

    def test_table_jump_member_exists(self) -> None:
        assert hasattr(InsnKind, "TABLE_JUMP")

    def test_table_jump_value_is_stable_string(self) -> None:
        """Enum values are part of the contract -- subscribers and
        diagnostics may match by string value, so the value is
        regression-pinned."""
        assert InsnKind.TABLE_JUMP.value == "table_jump"

    def test_table_jump_distinct_from_other_jump_kinds(self) -> None:
        """Dispatcher analyses must distinguish ``TABLE_JUMP`` from
        ``GOTO`` / ``COND_JUMP`` / ``EQUALITY_JUMP`` -- the whole
        point of adding the member is so switch-table dispatchers
        don't collide with unconditional or binary-conditional
        jumps."""
        distinct = {
            InsnKind.TABLE_JUMP,
            InsnKind.GOTO,
            InsnKind.COND_JUMP,
            InsnKind.EQUALITY_JUMP,
        }
        assert len(distinct) == 4

    def test_table_jump_not_unknown(self) -> None:
        """Sanity check: ``TABLE_JUMP`` is its own kind, not the
        ``UNKNOWN`` fallback."""
        assert InsnKind.TABLE_JUMP is not InsnKind.UNKNOWN
