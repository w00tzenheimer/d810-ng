"""Unit tests: ConstantSubtreeFoldRule skips m_ldc replacement for set/comparison opcodes.

These tests verify the fix for INTERR 50832: when ConstantSubtreeFoldRule folds
an instruction like ``setz %var.16, xdu.16(#0.8), zf.1``, the destination
operand ``zf.1`` is 1-bit, but the constant being folded is from a 16-bit
source.  Replacing the whole instruction with ``m_ldc #0.1, zf.1`` produces a
size mismatch that crashes IDA's verifier with INTERR 50832.

The fix adds ``_SET_OPCODES`` and guards the whole-instruction ``m_ldc``
replacement path so that set/comparison opcodes fall through to the partial-fold
path, which reconstructs the instruction from the folded AST while preserving
correct operand sizes.

Source-level approach rationale: importing the module requires ``ida_hexrays``
at the top level.  Since IDA is not available in CI unit tests, we verify the
fix via structural source checks — the same approach used by
``test_fold_readonlydata_mop_v.py``.
"""
from __future__ import annotations

import pathlib

_SRC = pathlib.Path(
    "src/d810/optimizers/microcode/instructions/peephole/fold_constant_subtree.py"
)


def _read_src() -> str:
    return _SRC.read_text()


class TestSetOpcodesGuardPresent:
    """Source-level checks: _SET_OPCODES frozenset exists and is populated."""

    def test_set_opcodes_frozenset_defined(self) -> None:
        """_SET_OPCODES must be defined as a frozenset."""
        src = _read_src()
        assert "_SET_OPCODES: frozenset[int] = frozenset({" in src, (
            "_SET_OPCODES frozenset must be defined in fold_constant_subtree.py"
        )

    def test_setz_in_set_opcodes(self) -> None:
        """m_setz must be listed in _SET_OPCODES."""
        src = _read_src()
        assert "ida_hexrays.m_setz," in src, (
            "m_setz must be in _SET_OPCODES to prevent INTERR 50832 on setz instructions"
        )

    def test_setnz_in_set_opcodes(self) -> None:
        """m_setnz must be listed in _SET_OPCODES."""
        src = _read_src()
        assert "ida_hexrays.m_setnz," in src, (
            "m_setnz must be in _SET_OPCODES"
        )

    def test_setb_in_set_opcodes(self) -> None:
        """m_setb must be listed in _SET_OPCODES."""
        src = _read_src()
        assert "ida_hexrays.m_setb," in src, (
            "m_setb must be in _SET_OPCODES"
        )

    def test_setl_in_set_opcodes(self) -> None:
        """m_setl must be listed in _SET_OPCODES."""
        src = _read_src()
        assert "ida_hexrays.m_setl," in src, (
            "m_setl must be in _SET_OPCODES"
        )

    def test_setp_in_set_opcodes(self) -> None:
        """m_setp must be listed in _SET_OPCODES."""
        src = _read_src()
        assert "ida_hexrays.m_setp," in src, (
            "m_setp must be in _SET_OPCODES"
        )

    def test_all_eleven_set_opcodes_present(self) -> None:
        """All eleven m_set* opcodes must appear in the source."""
        src = _read_src()
        expected = [
            "ida_hexrays.m_setz,",
            "ida_hexrays.m_setnz,",
            "ida_hexrays.m_setae,",
            "ida_hexrays.m_setb,",
            "ida_hexrays.m_seta,",
            "ida_hexrays.m_setbe,",
            "ida_hexrays.m_setg,",
            "ida_hexrays.m_setge,",
            "ida_hexrays.m_setl,",
            "ida_hexrays.m_setle,",
            "ida_hexrays.m_setp,",
        ]
        missing = [op for op in expected if op not in src]
        assert not missing, (
            f"These m_set* opcodes are missing from _SET_OPCODES: {missing}"
        )


class TestSetOpcodesGuardApplied:
    """Source-level checks: the whole-constant m_ldc path is guarded by _SET_OPCODES."""

    def test_value_check_guards_set_opcodes(self) -> None:
        """The whole-constant branch must check 'ins.opcode not in _SET_OPCODES'."""
        src = _read_src()
        assert "ins.opcode not in _SET_OPCODES" in src, (
            "The whole-constant m_ldc replacement must be guarded by "
            "'ins.opcode not in _SET_OPCODES' to prevent INTERR 50832"
        )

    def test_guard_is_on_value_check_line(self) -> None:
        """The guard must be on the same condition that checks 'value is not None'."""
        src = _read_src()
        assert "value is not None and ins.opcode not in _SET_OPCODES" in src, (
            "The INTERR 50832 fix requires combining the value-is-not-None check "
            "with the _SET_OPCODES guard on a single condition line"
        )

    def test_set_opcodes_appears_before_value_check(self) -> None:
        """_SET_OPCODES definition must appear before the check_and_replace method."""
        src = _read_src()
        pos_set = src.find("_SET_OPCODES: frozenset[int]")
        pos_check = src.find("def check_and_replace")
        assert pos_set != -1, "_SET_OPCODES must be defined"
        assert pos_check != -1, "check_and_replace must exist"
        assert pos_set < pos_check, (
            "_SET_OPCODES must be defined at module level before check_and_replace"
        )

    def test_skip_opcodes_unchanged(self) -> None:
        """_SKIP_OPCODES must still be present (regression guard)."""
        src = _read_src()
        assert "_SKIP_OPCODES: frozenset[int] = frozenset({" in src, (
            "_SKIP_OPCODES must still be present — this is a regression check"
        )
        assert "ida_hexrays.m_goto," in src, (
            "m_goto must still be in _SKIP_OPCODES — regression check"
        )

    def test_set_opcodes_separate_from_skip_opcodes(self) -> None:
        """_SET_OPCODES must be a separate frozenset from _SKIP_OPCODES."""
        src = _read_src()
        pos_skip = src.find("_SKIP_OPCODES: frozenset[int]")
        pos_set = src.find("_SET_OPCODES: frozenset[int]")
        assert pos_skip != -1, "_SKIP_OPCODES must exist"
        assert pos_set != -1, "_SET_OPCODES must exist"
        assert pos_skip != pos_set, (
            "_SET_OPCODES and _SKIP_OPCODES must be two separate frozenset definitions"
        )
